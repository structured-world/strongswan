/*
 * Copyright (C) 2025 Structured World Foundation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

/**
 * @defgroup dhcp_inform_db_provider dhcp_inform_db_provider
 * @{ @ingroup dhcp_inform
 */

#ifndef DHCP_INFORM_DB_PROVIDER_H_
#define DHCP_INFORM_DB_PROVIDER_H_

#include "dhcp_inform_provider.h"

typedef struct dhcp_inform_db_provider_t dhcp_inform_db_provider_t;

/**
 * Database route provider - reads routes from SQL database.
 *
 * Supports PostgreSQL, MySQL, SQLite via strongSwan database abstraction.
 * Queries routes from v_pool_routes view based on client virtual IP.
 *
 * Configuration:
 *   charon.plugins.dhcp-inform.database = pgsql://user:pass@host/db
 *
 * Required database schema:
 *   VIEW v_pool_routes (pool_cidr, route)
 *   - Returns routes for pools, client IP matched against pool_cidr
 */
struct dhcp_inform_db_provider_t {

	/**
	 * Implements dhcp_inform_provider_t interface
	 */
	dhcp_inform_provider_t provider;
};

/**
 * Create database route provider.
 *
 * @return				provider instance, NULL on failure
 */
dhcp_inform_db_provider_t *dhcp_inform_db_provider_create();

#endif /** DHCP_INFORM_DB_PROVIDER_H_ @}*/
