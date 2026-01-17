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
#include <database/database.h>
#include <selectors/traffic_selector.h>
#include <networking/host.h>

typedef struct private_dhcp_inform_db_provider_t private_dhcp_inform_db_provider_t;

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
};

/* Maximum CIDR string length for IPv4: "255.255.255.255/32" = 18 chars.
 * Note: DHCP option 121/249 (classless static routes) is IPv4-only.
 * Using 43 to be safe with any reasonable input. */
#define MAX_CIDR_LEN 43

/**
 * Parse CIDR to host and prefix.
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

	ts = traffic_selector_create_from_subnet(host, prefix, 0, 0, 65535);
	host->destroy(host);

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

METHOD(dhcp_inform_provider_t, get_routes, linked_list_t*,
	private_dhcp_inform_db_provider_t *this, const char *client_ip)
{
	linked_list_t *routes;
	enumerator_t *enumerator;
	char *pool_cidr, *route_value;
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

	/* Query all pool/route pairs, filter in C for database portability.
	 * Uses v_pool_routes VIEW: (pool_cidr, route).
	 * Works with PostgreSQL, MySQL, SQLite via strongSwan database abstraction.
	 */
	enumerator = this->db->query(this->db,
		"SELECT pool_cidr, route FROM v_pool_routes",
		DB_TEXT, DB_TEXT);

	if (!enumerator)
	{
		DBG1(DBG_CFG, "dhcp-inform-db: query failed");
		client->destroy(client);
		return routes;
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
			routes_added++;
			DBG2(DBG_CFG, "dhcp-inform-db: added route %s from pool %s",
				 route_value, pool_cidr);
		}
	}
	enumerator->destroy(enumerator);
	client->destroy(client);

	DBG1(DBG_CFG, "dhcp-inform-db: found %d routes for %s", routes_added, client_ip);

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

METHOD(dhcp_inform_provider_t, destroy, void,
	private_dhcp_inform_db_provider_t *this)
{
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
		},
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
