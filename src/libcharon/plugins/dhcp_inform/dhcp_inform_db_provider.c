/*
 * Copyright (C) 2025 Structured World Foundation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include "dhcp_inform_db_provider.h"

#include <daemon.h>
#include <collections/linked_list.h>
#include <collections/hashtable.h>
#include <database/database.h>
#include <selectors/traffic_selector.h>
#include <networking/host.h>
#include <threading/mutex.h>
#include <processing/jobs/callback_job.h>

#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

/**
 * How long a resolved FQDN stays cached, in seconds
 */
#define FQDN_CACHE_TTL 300

/**
 * How long a failed resolution is remembered before retrying, in seconds
 */
#define FQDN_NEGATIVE_TTL 60

typedef struct private_dhcp_inform_db_provider_t private_dhcp_inform_db_provider_t;

/**
 * Cached FQDN resolution
 */
typedef struct {
	/** resolved address, network byte order; 0 while unresolved or failed */
	uint32_t addr;
	/** monotonic time after which a refresh becomes due */
	time_t expires;
	/** the name is queued for background resolution */
	bool resolving;
} fqdn_entry_t;

/**
 * Private data
 */
struct private_dhcp_inform_db_provider_t {

	/**
	 * Public interface
	 */
	dhcp_inform_db_provider_t public;

	/**
	 * Database connection
	 */
	database_t *db;

	/**
	 * FQDN resolution cache, fqdn string => fqdn_entry_t
	 */
	hashtable_t *fqdn_cache;

	/**
	 * Lock for the FQDN cache and the pending queue
	 */
	mutex_t *mutex;

	/**
	 * FQDNs queued for background resolution, char*, owned
	 */
	linked_list_t *pending;

	/**
	 * The single resolver job is queued or running
	 */
	bool resolver_active;
};

/* Maximum CIDR string length for IPv4: "255.255.255.255/32" = 18 chars.
 * Note: DHCP option 121/249 (classless static routes) is IPv4-only.
 * Using 43 to be safe with any reasonable input. */
#define MAX_CIDR_LEN 43

/**
 * Parse CIDR to host and prefix.
 * Prefix 0 (match-all) is allowed for admin flexibility.
 * Note: Duplicated for self-contained compilation (see static_provider).
 */
static bool parse_cidr_to_host(const char *cidr, host_t **host, uint8_t *prefix)
{
	char *slash, *ip_str, *endptr;
	long pfx = 32;

	if (!cidr || !*cidr || strlen(cidr) > MAX_CIDR_LEN)
	{
		return FALSE;
	}

	ip_str = strdup(cidr);
	if (!ip_str)
	{
		return FALSE;
	}

	slash = strchr(ip_str, '/');
	if (slash)
	{
		*slash = '\0';
		pfx = strtol(slash + 1, &endptr, 10);
		if (*endptr != '\0' || pfx < 0 || pfx > 32)
		{
			free(ip_str);
			return FALSE;
		}
	}

	*host = host_create_from_string(ip_str, 0);
	free(ip_str);

	if (!*host)
	{
		return FALSE;
	}

	*prefix = pfx;
	return TRUE;
}

/**
 * Parse CIDR notation to traffic_selector.
 * Note: This function is intentionally duplicated in each provider file to keep
 * providers self-contained and independently compilable without shared utilities.
 */
static traffic_selector_t *parse_cidr(const char *cidr)
{
	host_t *host;
	uint8_t prefix;
	traffic_selector_t *ts;

	if (!parse_cidr_to_host(cidr, &host, &prefix))
	{
		DBG1(DBG_CFG, "dhcp-inform-db: failed to parse CIDR: %s", cidr);
		return NULL;
	}

	/* the constructor adopts and destroys the host */
	ts = traffic_selector_create_from_subnet(host, prefix, 0, 0, 65535);

	return ts;
}

/**
 * Check if an IP address falls within a network/prefix.
 * Note: Duplicated from static_provider for self-contained compilation.
 */
static bool ip_in_subnet(host_t *ip, host_t *network, uint8_t prefix)
{
	chunk_t ip_addr, net_addr;
	uint8_t *ip_ptr, *net_ptr;
	int bytes, bits, i;
	uint8_t mask;

	if (ip->get_family(ip) != network->get_family(network))
	{
		return FALSE;
	}

	ip_addr = ip->get_address(ip);
	net_addr = network->get_address(network);

	if (ip_addr.len != net_addr.len)
	{
		return FALSE;
	}

	bytes = prefix / 8;
	bits = prefix % 8;

	ip_ptr = ip_addr.ptr;
	net_ptr = net_addr.ptr;

	/* Compare full bytes. Cast is safe: ip_addr.len is always <= 16 (IPv6) */
	for (i = 0; i < bytes && i < (int)ip_addr.len; i++)
	{
		if (ip_ptr[i] != net_ptr[i])
		{
			return FALSE;
		}
	}

	/* Compare remaining bits */
	if (bits > 0 && bytes < (int)ip_addr.len)
	{
		mask = 0xFF << (8 - bits);
		if ((ip_ptr[bytes] & mask) != (net_ptr[bytes] & mask))
		{
			return FALSE;
		}
	}

	return TRUE;
}

/**
 * Drain the pending queue on a single worker thread: names resolve one at
 * a time, so a slow resolver occupies at most one of charon's processor
 * threads no matter how many names are queued. The provider outlives the
 * job: the daemon cancels all processor jobs before plugins unload.
 */
static job_requeue_t resolve_pending_job(private_dhcp_inform_db_provider_t *this)
{
	struct addrinfo hints, *res;
	fqdn_entry_t *entry;
	uint32_t ip_addr;
	char *fqdn;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	while (TRUE)
	{
		this->mutex->lock(this->mutex);
		if (this->pending->get_first(this->pending, (void**)&fqdn) != SUCCESS)
		{
			this->resolver_active = FALSE;
			this->mutex->unlock(this->mutex);
			return JOB_REQUEUE_NONE;
		}
		this->mutex->unlock(this->mutex);

		/* the head entry stays queued while it resolves: producers only
		 * append, and on job cancellation the list still owns the string */
		ip_addr = 0;
		if (getaddrinfo(fqdn, NULL, &hints, &res) == 0)
		{
			if (res->ai_family == AF_INET)
			{
				struct sockaddr_in *sin = (struct sockaddr_in*)res->ai_addr;
				ip_addr = sin->sin_addr.s_addr;
			}
			freeaddrinfo(res);
			DBG2(DBG_CFG, "dhcp-inform-db: resolved FQDN %s", fqdn);
		}
		else
		{
			DBG1(DBG_CFG, "dhcp-inform-db: failed to resolve FQDN: %s", fqdn);
		}

		this->mutex->lock(this->mutex);
		entry = this->fqdn_cache->get(this->fqdn_cache, fqdn);
		if (entry)
		{
			if (ip_addr)
			{
				entry->addr = ip_addr;
			}
			/* a failed refresh keeps the last known address serving and only
			 * shortens the interval until the next attempt */
			entry->expires = time_monotonic(NULL) +
							 (ip_addr ? FQDN_CACHE_TTL : FQDN_NEGATIVE_TTL);
			entry->resolving = FALSE;
		}
		this->pending->remove_first(this->pending, (void**)&fqdn);
		this->mutex->unlock(this->mutex);
		free(fqdn);
	}
}

/**
 * Queue a name for background resolution; the caller holds the mutex and
 * has already marked the cache entry as resolving
 */
static void queue_resolution(private_dhcp_inform_db_provider_t *this,
							 const char *fqdn)
{
	this->pending->insert_last(this->pending, strdup(fqdn));
	if (!this->resolver_active)
	{
		this->resolver_active = TRUE;
		lib->processor->queue_job(lib->processor,
			(job_t*)callback_job_create((callback_job_cb_t)resolve_pending_job,
										this, NULL, callback_job_cancel_thread));
	}
}

/**
 * Queue background resolutions for every fqdn resource already present in
 * v_user_routes, so the cache is warm before the first DHCPINFORM arrives
 * and cold names cost a route only when added to the database at runtime
 */
METHOD(dhcp_inform_db_provider_t, prewarm, void,
	private_dhcp_inform_db_provider_t *this)
{
	enumerator_t *enumerator;
	fqdn_entry_t *entry;
	char *fqdn;

	if (!this->db)
	{
		return;
	}

	enumerator = this->db->query(this->db,
		"SELECT DISTINCT resource_value FROM v_user_routes "
		"WHERE resource_type = 'fqdn'",
		DB_TEXT);
	if (!enumerator)
	{
		return;
	}

	while (enumerator->enumerate(enumerator, &fqdn))
	{
		if (!fqdn || !*fqdn)
		{
			continue;
		}
		this->mutex->lock(this->mutex);
		entry = this->fqdn_cache->get(this->fqdn_cache, fqdn);
		if (!entry)
		{
			INIT(entry,
				.resolving = TRUE,
			);
			this->fqdn_cache->put(this->fqdn_cache, strdup(fqdn), entry);
			queue_resolution(this, fqdn);
		}
		this->mutex->unlock(this->mutex);
	}
	enumerator->destroy(enumerator);
}

/**
 * Look an FQDN up in the cache, 0 when no address is known (yet).
 * The request path never resolves: a miss or a due refresh queues a
 * background job, and an expired entry keeps serving its last address
 * until the refresh lands, so routes never drop in steady state.
 */
static uint32_t resolve_fqdn(private_dhcp_inform_db_provider_t *this,
							 const char *fqdn)
{
	fqdn_entry_t *entry;
	uint32_t ip_addr = 0;
	time_t now;

	now = time_monotonic(NULL);

	this->mutex->lock(this->mutex);
	entry = this->fqdn_cache->get(this->fqdn_cache, (void*)fqdn);
	if (!entry)
	{
		INIT(entry);
		this->fqdn_cache->put(this->fqdn_cache, strdup(fqdn), entry);
	}
	ip_addr = entry->addr;
	if (entry->expires <= now && !entry->resolving)
	{
		entry->resolving = TRUE;
		queue_resolution(this, fqdn);
	}
	this->mutex->unlock(this->mutex);

	return ip_addr;
}

/**
 * Build a traffic selector from a v_user_routes resource:
 * "ip" and "fqdn" become host routes, "cidr" a subnet route.
 * DHCP options 121/249 encode IPv4 only, so other families are skipped.
 */
static traffic_selector_t *resource_to_ts(private_dhcp_inform_db_provider_t *this,
										  const char *type, const char *value)
{
	traffic_selector_t *ts = NULL;
	host_t *host;

	if (streq(type, "ip"))
	{
		host = host_create_from_string((char*)value, 0);
		if (host)
		{
			if (host->get_family(host) == AF_INET)
			{
				ts = traffic_selector_create_from_subnet(host, 32, 0, 0, 65535);
			}
			else
			{
				DBG1(DBG_CFG, "dhcp-inform-db: ignoring non-IPv4 ip resource %s",
					 value);
				host->destroy(host);
			}
		}
	}
	else if (streq(type, "cidr"))
	{
		ts = parse_cidr(value);
		if (ts && ts->get_type(ts) != TS_IPV4_ADDR_RANGE)
		{
			DBG1(DBG_CFG, "dhcp-inform-db: ignoring non-IPv4 cidr resource %s",
				 value);
			ts->destroy(ts);
			ts = NULL;
		}
	}
	else if (streq(type, "fqdn"))
	{
		uint32_t ip_addr = resolve_fqdn(this, value);

		if (ip_addr)
		{
			host = host_create_from_chunk(AF_INET,
					chunk_create((char*)&ip_addr, 4), 0);
			if (host)
			{
				ts = traffic_selector_create_from_subnet(host, 32, 0, 0, 65535);
			}
		}
	}
	else
	{
		DBG2(DBG_CFG, "dhcp-inform-db: unknown resource type=%s value=%s",
			 type, value);
	}

	return ts;
}

/**
 * Add per-identity routes from the v_user_routes VIEW:
 * (identity, resource_type, resource_value). The identity is matched
 * without a domain part, so user@example.org looks up as "user".
 * A missing view is not an error, deployments may use v_pool_routes only.
 */
static int add_identity_routes(private_dhcp_inform_db_provider_t *this,
							   identification_t *identity,
							   linked_list_t *routes)
{
	enumerator_t *enumerator;
	char identity_str[256], *at;
	char *resource_type, *resource_value;
	int added = 0, written;

	/* use the printable form: get_encoding() would return raw DER for
	 * DN identities, which is no valid text lookup key */
	written = snprintf(identity_str, sizeof(identity_str), "%Y", identity);
	if (written < 0 || written >= (int)sizeof(identity_str))
	{
		DBG1(DBG_CFG, "dhcp-inform-db: identity too long for route lookup");
		return 0;
	}
	/* strip the domain part of mail-style identities only; a DN can
	 * legitimately contain '@' inside an emailAddress component */
	if (identity->get_type(identity) == ID_RFC822_ADDR)
	{
		at = strchr(identity_str, '@');
		if (at)
		{
			*at = '\0';
		}
	}

	DBG2(DBG_CFG, "dhcp-inform-db: looking up routes for identity %s",
		 identity_str);

	enumerator = this->db->query(this->db,
		"SELECT resource_type, resource_value FROM v_user_routes "
		"WHERE identity = ?",
		DB_TEXT, identity_str,
		DB_TEXT, DB_TEXT);

	if (!enumerator)
	{
		DBG2(DBG_CFG, "dhcp-inform-db: v_user_routes not available");
		return 0;
	}

	while (enumerator->enumerate(enumerator, &resource_type, &resource_value))
	{
		traffic_selector_t *ts;

		if (!resource_type || !resource_value)
		{
			continue;
		}

		ts = resource_to_ts(this, resource_type, resource_value);
		if (ts)
		{
			routes->insert_last(routes, ts);
			added++;
			DBG2(DBG_CFG, "dhcp-inform-db: added route %R for %s",
				 ts, identity_str);
		}
	}
	enumerator->destroy(enumerator);

	if (added)
	{
		DBG1(DBG_CFG, "dhcp-inform-db: found %d routes for identity %s",
			 added, identity_str);
	}

	return added;
}

/**
 * Add per-pool routes from the v_pool_routes VIEW: (pool_cidr, route).
 * All pairs are fetched and filtered in C for database portability
 * (works with PostgreSQL, MySQL, SQLite via the database abstraction).
 */
static int add_pool_routes(private_dhcp_inform_db_provider_t *this,
						   host_t *client, linked_list_t *routes)
{
	enumerator_t *enumerator;
	char *pool_cidr, *route_value;
	int added = 0;

	enumerator = this->db->query(this->db,
		"SELECT pool_cidr, route FROM v_pool_routes",
		DB_TEXT, DB_TEXT);

	if (!enumerator)
	{
		DBG2(DBG_CFG, "dhcp-inform-db: v_pool_routes not available");
		return 0;
	}

	while (enumerator->enumerate(enumerator, &pool_cidr, &route_value))
	{
		host_t *pool_net;
		uint8_t pool_prefix;
		traffic_selector_t *ts;

		if (!pool_cidr || !route_value)
		{
			continue;
		}

		/* Parse pool CIDR and check if client IP is in this pool */
		if (!parse_cidr_to_host(pool_cidr, &pool_net, &pool_prefix))
		{
			DBG2(DBG_CFG, "dhcp-inform-db: invalid pool CIDR: %s", pool_cidr);
			continue;
		}

		if (!ip_in_subnet(client, pool_net, pool_prefix))
		{
			pool_net->destroy(pool_net);
			continue;
		}
		pool_net->destroy(pool_net);

		/* Client is in this pool - add the route */
		ts = parse_cidr(route_value);
		if (ts)
		{
			routes->insert_last(routes, ts);
			added++;
			DBG2(DBG_CFG, "dhcp-inform-db: added route %s from pool %s",
				 route_value, pool_cidr);
		}
	}
	enumerator->destroy(enumerator);

	return added;
}

METHOD(dhcp_inform_provider_t, get_routes, linked_list_t*,
	private_dhcp_inform_db_provider_t *this, const char *client_ip,
	identification_t *identity)
{
	linked_list_t *routes;
	host_t *client;
	int routes_added = 0;

	routes = linked_list_create();
	if (!routes)
	{
		return NULL;
	}

	if (!this->db)
	{
		return routes;
	}

	if (!client_ip || !*client_ip)
	{
		DBG1(DBG_CFG, "dhcp-inform-db: empty client IP");
		return routes;
	}

	client = host_create_from_string((char*)client_ip, 0);
	if (!client)
	{
		DBG1(DBG_CFG, "dhcp-inform-db: invalid client IP: %s", client_ip);
		return routes;
	}

	DBG2(DBG_CFG, "dhcp-inform-db: looking up routes for IP %s", client_ip);

	/* Per-identity routes first, per-pool routes on top; the responder
	 * deduplicates overlapping entries */
	if (identity)
	{
		routes_added += add_identity_routes(this, identity, routes);
	}
	routes_added += add_pool_routes(this, client, routes);

	client->destroy(client);

	DBG1(DBG_CFG, "dhcp-inform-db: found %d routes for %s", routes_added,
		 client_ip);

	return routes;
}

METHOD(dhcp_inform_provider_t, get_name, const char*,
	private_dhcp_inform_db_provider_t *this)
{
	return "database";
}

METHOD(dhcp_inform_provider_t, is_available, bool,
	private_dhcp_inform_db_provider_t *this)
{
	return this->db != NULL;
}

/**
 * Free an FQDN cache entry and its key
 */
static void fqdn_entry_destroy(void *val, const void *key)
{
	free(val);
	free((void*)key);
}

METHOD(dhcp_inform_provider_t, destroy, void,
	private_dhcp_inform_db_provider_t *this)
{
	this->fqdn_cache->destroy_function(this->fqdn_cache, fqdn_entry_destroy);
	this->pending->destroy_function(this->pending, free);
	this->mutex->destroy(this->mutex);
	DESTROY_IF(this->db);
	free(this);
}

/**
 * See header
 */
dhcp_inform_db_provider_t *dhcp_inform_db_provider_create()
{
	private_dhcp_inform_db_provider_t *this;
	char *db_uri;

	INIT(this,
		.public = {
			.provider = {
				.get_routes = _get_routes,
				.get_name = _get_name,
				.is_available = _is_available,
				.destroy = _destroy,
			},
			.prewarm = _prewarm,
		},
		.fqdn_cache = hashtable_create(hashtable_hash_str,
									   hashtable_equals_str, 4),
		.pending = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	/* Get database URI from configuration */
	db_uri = lib->settings->get_str(lib->settings,
		"%s.plugins.dhcp-inform.database", NULL, lib->ns);

	if (db_uri)
	{
		this->db = lib->db->create(lib->db, db_uri);
		if (this->db)
		{
			DBG1(DBG_CFG, "dhcp-inform: database provider connected");
		}
		else
		{
			DBG1(DBG_CFG, "dhcp-inform: failed to connect to database, "
				 "database provider disabled");
		}
	}
	else
	{
		DBG2(DBG_CFG, "dhcp-inform: no database configured, "
			 "database provider disabled");
	}

	return &this->public;
}
