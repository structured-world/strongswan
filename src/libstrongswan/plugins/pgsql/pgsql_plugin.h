/*
 * Copyright (C) 2025 Lantec / ULA Software
 * Based on mysql_plugin.h by Martin Willi
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

/**
 * @defgroup pgsql_p pgsql
 * @ingroup plugins
 *
 * @defgroup pgsql_plugin pgsql_plugin
 * @{ @ingroup pgsql_p
 */

#ifndef PGSQL_PLUGIN_H_
#define PGSQL_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct pgsql_plugin_t pgsql_plugin_t;

/**
 * Plugin implementing PostgreSQL database connectivity.
 */
struct pgsql_plugin_t {

	/**
	 * Implements plugin_t interface.
	 */
	plugin_t plugin;
};

#endif /** PGSQL_PLUGIN_H_ @}*/
