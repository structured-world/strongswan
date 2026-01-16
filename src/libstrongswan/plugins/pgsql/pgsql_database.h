/*
 * Copyright (C) 2025 Structured World Foundation
 * Based on mysql_database.h by Martin Willi
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

/**
 * @defgroup pgsql_database pgsql_database
 * @{ @ingroup pgsql_p
 */

#ifndef PGSQL_DATABASE_H_
#define PGSQL_DATABASE_H_

#include <database/database.h>

typedef struct pgsql_database_t pgsql_database_t;

/**
 * PostgreSQL database_t implementation.
 */
struct pgsql_database_t {

	/**
	 * Implements database_t
	 */
	database_t db;
};

/**
 * Initialize PostgreSQL library.
 *
 * @return			TRUE if initialization successful
 */
bool pgsql_database_init();

/**
 * Deinitialize PostgreSQL library.
 */
void pgsql_database_deinit();

/**
 * Create a pgsql_database instance.
 *
 * @param uri		connection URI, postgresql://user:pass@host:port/database
 * @return			database instance, NULL on failure
 */
pgsql_database_t *pgsql_database_create(char *uri);

#endif /** PGSQL_DATABASE_H_ @}*/
