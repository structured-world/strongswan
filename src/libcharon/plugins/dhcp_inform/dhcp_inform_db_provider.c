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

/**
 * Parse CIDR notation to traffic_selector
 */
static traffic_selector_t *parse_cidr(const char *cidr)
{
	char *slash, *ip_str;
	int prefix = 32;
	host_t *host;
	traffic_selector_t *ts = NULL;

	if (!cidr || !*cidr)
	{
		DBG1(DBG_CFG, "dhcp-inform-db: CORRUPTED DATA - empty CIDR");
		return NULL;
	}

	if (strlen(cidr) > 43)
	{
		DBG1(DBG_CFG, "dhcp-inform-db: CORRUPTED DATA - CIDR too long: %.20s...",
			 cidr);
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
		prefix = atoi(slash + 1);
		if (prefix < 0 || prefix > 32)
		{
			DBG1(DBG_CFG, "dhcp-inform-db: invalid prefix %d in %s",
				 prefix, cidr);
			free(ip_str);
			return NULL;
		}
	}

	host = host_create_from_string(ip_str, 0);
	if (!host)
	{
		DBG1(DBG_CFG, "dhcp-inform-db: invalid IP in CIDR: %s", ip_str);
		free(ip_str);
		return NULL;
	}

	ts = traffic_selector_create_from_subnet(host, prefix, 0, 0, 65535);
	host->destroy(host);
	free(ip_str);

	return ts;
}

METHOD(dhcp_inform_provider_t, get_routes, linked_list_t*,
	private_dhcp_inform_db_provider_t *this, const char *client_ip)
{
	linked_list_t *routes;
	enumerator_t *enumerator;
	char *route_value;
	int routes_parsed = 0;
	int routes_failed = 0;

	routes = linked_list_create();

	if (!this->db)
	{
		return routes;
	}

	if (!client_ip || !*client_ip)
	{
		DBG1(DBG_CFG, "dhcp-inform-db: CORRUPTED DATA - empty client IP");
		return routes;
	}

	DBG2(DBG_CFG, "dhcp-inform-db: looking up routes for IP %s", client_ip);

	/* Query routes for the pool that contains this IP
	 * Uses v_pool_routes VIEW: (pool_cidr, route)
	 */
	enumerator = this->db->query(this->db,
		"SELECT route FROM v_pool_routes WHERE ?::inet << pool_cidr::inet",
		DB_TEXT, client_ip,
		DB_TEXT);

	if (!enumerator)
	{
		DBG2(DBG_CFG, "dhcp-inform-db: primary query failed, trying fallback");
		/* Fallback: get routes from auto_ip_pools directly */
		enumerator = this->db->query(this->db,
			"SELECT unnest(aip.routes) as route "
			"FROM auto_ip_pools aip "
			"JOIN environments e ON e.auto_ip_pool_id = aip.id "
			"WHERE e.is_active = true "
			"AND ?::inet << aip.cidr::inet",
			DB_TEXT, client_ip,
			DB_TEXT);
	}

	if (!enumerator)
	{
		DBG1(DBG_CFG, "dhcp-inform-db: all queries failed for %s", client_ip);
		return routes;
	}

	while (enumerator->enumerate(enumerator, &route_value))
	{
		traffic_selector_t *ts;

		routes_parsed++;

		if (!route_value)
		{
			DBG1(DBG_CFG, "dhcp-inform-db: CORRUPTED DATA - NULL route at row %d",
				 routes_parsed);
			routes_failed++;
			continue;
		}

		ts = parse_cidr(route_value);
		if (ts)
		{
			routes->insert_last(routes, ts);
			DBG2(DBG_CFG, "dhcp-inform-db: added route %s", route_value);
		}
		else
		{
			DBG1(DBG_CFG, "dhcp-inform-db: failed to parse route: %s",
				 route_value);
			routes_failed++;
		}
	}
	enumerator->destroy(enumerator);

	if (routes_failed > 0)
	{
		DBG1(DBG_CFG, "dhcp-inform-db: WARNING - %d/%d routes had corrupted data",
			 routes_failed, routes_parsed);
	}

	DBG1(DBG_CFG, "dhcp-inform-db: found %d valid routes for %s",
		 routes->get_count(routes), client_ip);

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
