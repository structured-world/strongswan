/*
 * Copyright (C) 2025 Structured World Foundation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include "dhcp_inform_static_provider.h"

#include <daemon.h>
#include <collections/linked_list.h>
#include <networking/host.h>
#include <selectors/traffic_selector.h>

typedef struct private_dhcp_inform_static_provider_t private_dhcp_inform_static_provider_t;

/**
 * Pool configuration entry
 */
typedef struct {
	/** Pool name (informational) */
	char *name;
	/** Pool CIDR as host_t with prefix */
	host_t *network;
	/** Prefix length */
	uint8_t prefix;
	/** Routes for this pool */
	linked_list_t *routes;
} pool_entry_t;

/**
 * Private data
 */
struct private_dhcp_inform_static_provider_t {

	/**
	 * Public interface
	 */
	dhcp_inform_static_provider_t public;

	/**
	 * Global routes (apply to all clients not matching a pool)
	 */
	linked_list_t *global_routes;

	/**
	 * Per-pool route configurations
	 */
	linked_list_t *pools;

	/**
	 * Whether any routes are configured
	 */
	bool has_routes;
};

/**
 * Destroy a pool entry
 */
static void pool_entry_destroy(pool_entry_t *entry)
{
	if (entry)
	{
		free(entry->name);
		DESTROY_IF(entry->network);
		if (entry->routes)
		{
			entry->routes->destroy_offset(entry->routes,
				offsetof(traffic_selector_t, destroy));
		}
		free(entry);
	}
}

/* Maximum CIDR string length for IPv4: "255.255.255.255/32" = 18 chars.
 * Note: DHCP option 121/249 (classless static routes) is IPv4-only.
 * Using 43 to be safe with any reasonable input. */
#define MAX_CIDR_LEN 43

/**
 * Parse CIDR notation to traffic_selector.
 * Note: This function is intentionally duplicated in each provider file to keep
 * providers self-contained and independently compilable without shared utilities.
 *
 * Prefix 0 (/0, default route) is allowed here for admin flexibility.
 * The TS provider filters out /0 routes since we don't want to push
 * default routes extracted from traffic selectors.
 */
static traffic_selector_t *parse_cidr(const char *cidr)
{
	char *slash, *ip_str, *endptr;
	long prefix = 32;
	host_t *host;
	traffic_selector_t *ts = NULL;

	if (!cidr || !*cidr)
	{
		return NULL;
	}

	if (strlen(cidr) > MAX_CIDR_LEN)
	{
		DBG1(DBG_CFG, "dhcp-inform: CIDR too long: %.20s...", cidr);
		return NULL;
	}

	ip_str = strdup(cidr);
	if (!ip_str)
	{
		return NULL;
	}

	slash = strchr(ip_str, '/');
	if (slash)
	{
		*slash = '\0';
		prefix = strtol(slash + 1, &endptr, 10);
		if (*endptr != '\0' || prefix < 0 || prefix > 32)
		{
			DBG1(DBG_CFG, "dhcp-inform: invalid prefix in %s", cidr);
			free(ip_str);
			return NULL;
		}
	}

	host = host_create_from_string(ip_str, 0);
	if (!host)
	{
		DBG1(DBG_CFG, "dhcp-inform: invalid IP in CIDR: %s", ip_str);
		free(ip_str);
		return NULL;
	}

	ts = traffic_selector_create_from_subnet(host, prefix, 0, 0, 65535);
	host->destroy(host);
	free(ip_str);

	return ts;
}

/**
 * Parse CIDR to host and prefix for pool matching.
 * Prefix 0 (match-all) is allowed for admin flexibility.
 * Note: Duplicated for self-contained compilation (see parse_cidr comment).
 */
static bool parse_cidr_to_host(const char *cidr, host_t **host, uint8_t *prefix)
{
	char *slash, *ip_str, *endptr;
	long pfx = 32;

	if (!cidr || !*cidr)
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
 * Check if an IP address falls within a network/prefix
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

	/* Compare remaining bits. Cast is safe: ip_addr.len is always <= 16 (IPv6) */
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
 * Load routes from a config section
 */
static linked_list_t *load_routes_from_section(const char *section)
{
	linked_list_t *routes;
	enumerator_t *enumerator;
	char *key, *value;
	int count = 0;

	routes = linked_list_create();
	if (!routes)
	{
		return NULL;
	}

	enumerator = lib->settings->create_key_value_enumerator(lib->settings,
		"%s.plugins.dhcp-inform.%s", lib->ns, section);

	while (enumerator->enumerate(enumerator, &key, &value))
	{
		traffic_selector_t *ts = parse_cidr(value);
		if (ts)
		{
			routes->insert_last(routes, ts);
			count++;
			DBG2(DBG_CFG, "dhcp-inform: loaded static route %s from %s",
				 value, section);
		}
		else
		{
			DBG1(DBG_CFG, "dhcp-inform: failed to parse route '%s' in %s",
				 value, section);
		}
	}
	enumerator->destroy(enumerator);

	return routes;
}

/**
 * Load pool configurations
 */
static void load_pools(private_dhcp_inform_static_provider_t *this)
{
	enumerator_t *pool_enum;
	char *pool_name;

	pool_enum = lib->settings->create_section_enumerator(lib->settings,
		"%s.plugins.dhcp-inform.pools", lib->ns);

	while (pool_enum->enumerate(pool_enum, &pool_name))
	{
		char *cidr;
		char routes_section[256];
		pool_entry_t *entry;
		host_t *network;
		uint8_t prefix;

		cidr = lib->settings->get_str(lib->settings,
			"%s.plugins.dhcp-inform.pools.%s.cidr", NULL, lib->ns, pool_name);

		if (!cidr)
		{
			DBG1(DBG_CFG, "dhcp-inform: pool '%s' missing cidr, skipping",
				 pool_name);
			continue;
		}

		if (!parse_cidr_to_host(cidr, &network, &prefix))
		{
			DBG1(DBG_CFG, "dhcp-inform: pool '%s' invalid cidr '%s', skipping",
				 pool_name, cidr);
			continue;
		}

		INIT(entry,
			.name = strdup(pool_name),
			.network = network,
			.prefix = prefix,
		);

		if (!entry->name)
		{
			DBG1(DBG_CFG, "dhcp-inform: failed to allocate name for pool '%s'",
				 pool_name);
			pool_entry_destroy(entry);
			continue;
		}

		int len = snprintf(routes_section, sizeof(routes_section),
						   "pools.%s.routes", pool_name);
		if (len < 0 || len >= (int)sizeof(routes_section))
		{
			DBG1(DBG_CFG, "dhcp-inform: pool name '%s' too long, skipping",
				 pool_name);
			pool_entry_destroy(entry);
			continue;
		}
		entry->routes = load_routes_from_section(routes_section);

		if (!entry->routes)
		{
			DBG1(DBG_CFG, "dhcp-inform: failed to load routes for pool '%s'",
				 pool_name);
			pool_entry_destroy(entry);
			continue;
		}

		if (entry->routes->get_count(entry->routes) > 0)
		{
			this->pools->insert_last(this->pools, entry);
			this->has_routes = TRUE;
			DBG1(DBG_CFG, "dhcp-inform: loaded pool '%s' (%s) with %d routes",
				 pool_name, cidr, entry->routes->get_count(entry->routes));
		}
		else
		{
			DBG1(DBG_CFG, "dhcp-inform: pool '%s' has no routes, skipping",
				 pool_name);
			pool_entry_destroy(entry);
		}
	}
	pool_enum->destroy(pool_enum);
}

/**
 * Clone routes from a list
 */
static linked_list_t *clone_routes(linked_list_t *source)
{
	linked_list_t *cloned;
	enumerator_t *enumerator;
	traffic_selector_t *ts, *clone;

	cloned = linked_list_create();
	if (!cloned)
	{
		return NULL;
	}
	enumerator = source->create_enumerator(source);
	while (enumerator->enumerate(enumerator, &ts))
	{
		clone = ts->clone(ts);
		if (!clone)
		{
			DBG1(DBG_CFG, "dhcp-inform: failed to clone traffic selector");
			continue;
		}
		cloned->insert_last(cloned, clone);
	}
	enumerator->destroy(enumerator);

	return cloned;
}

METHOD(dhcp_inform_provider_t, get_routes, linked_list_t*,
	private_dhcp_inform_static_provider_t *this, const char *client_ip)
{
	enumerator_t *enumerator;
	pool_entry_t *pool;
	host_t *client;

	if (!client_ip)
	{
		/* No client IP - return global routes */
		if (this->global_routes &&
			this->global_routes->get_count(this->global_routes) > 0)
		{
			DBG2(DBG_CFG, "dhcp-inform: returning global routes (no client IP)");
			return clone_routes(this->global_routes);
		}
		return linked_list_create();
	}

	client = host_create_from_string((char*)client_ip, 0);
	if (!client)
	{
		DBG1(DBG_CFG, "dhcp-inform: invalid client IP: %s", client_ip);
		return linked_list_create();
	}

	/* Check pool-specific routes first */
	enumerator = this->pools->create_enumerator(this->pools);
	while (enumerator->enumerate(enumerator, &pool))
	{
		if (ip_in_subnet(client, pool->network, pool->prefix))
		{
			enumerator->destroy(enumerator);
			client->destroy(client);

			DBG1(DBG_CFG, "dhcp-inform: client %s matched pool '%s', "
				 "returning %d pool-specific routes",
				 client_ip, pool->name, pool->routes->get_count(pool->routes));

			return clone_routes(pool->routes);
		}
	}
	enumerator->destroy(enumerator);
	client->destroy(client);

	/* Fall back to global routes */
	if (this->global_routes &&
		this->global_routes->get_count(this->global_routes) > 0)
	{
		DBG1(DBG_CFG, "dhcp-inform: client %s using %d global routes",
			 client_ip, this->global_routes->get_count(this->global_routes));
		return clone_routes(this->global_routes);
	}

	DBG1(DBG_CFG, "dhcp-inform: no routes configured for client %s", client_ip);
	return linked_list_create();
}

METHOD(dhcp_inform_provider_t, get_name, const char*,
	private_dhcp_inform_static_provider_t *this)
{
	return "static";
}

METHOD(dhcp_inform_provider_t, is_available, bool,
	private_dhcp_inform_static_provider_t *this)
{
	return this->has_routes;
}

METHOD(dhcp_inform_provider_t, destroy, void,
	private_dhcp_inform_static_provider_t *this)
{
	if (this->global_routes)
	{
		this->global_routes->destroy_offset(this->global_routes,
			offsetof(traffic_selector_t, destroy));
	}
	if (this->pools)
	{
		this->pools->destroy_function(this->pools, (void*)pool_entry_destroy);
	}
	free(this);
}

/**
 * See header
 */
dhcp_inform_static_provider_t *dhcp_inform_static_provider_create()
{
	private_dhcp_inform_static_provider_t *this;

	INIT(this,
		.public = {
			.provider = {
				.get_routes = _get_routes,
				.get_name = _get_name,
				.is_available = _is_available,
				.destroy = _destroy,
			},
		},
		.pools = linked_list_create(),
		.has_routes = FALSE,
	);

	if (!this->pools)
	{
		DBG1(DBG_CFG, "dhcp-inform: failed to create pools list");
		free(this);
		return NULL;
	}

	/* Load global routes */
	this->global_routes = load_routes_from_section("routes");
	if (this->global_routes &&
		this->global_routes->get_count(this->global_routes) > 0)
	{
		this->has_routes = TRUE;
		DBG1(DBG_CFG, "dhcp-inform: loaded %d global static routes",
			 this->global_routes->get_count(this->global_routes));
	}

	/* Load per-pool routes */
	load_pools(this);

	if (!this->has_routes)
	{
		DBG2(DBG_CFG, "dhcp-inform: no static routes configured");
	}

	return &this->public;
}
