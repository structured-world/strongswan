/*
 * Copyright (C) 2025 Lantec / ULA Software
 * Based on mysql_plugin.c by Martin Willi
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include "pgsql_plugin.h"

#include <library.h>
#include <utils/debug.h>
#include "pgsql_database.h"

typedef struct private_pgsql_plugin_t private_pgsql_plugin_t;

/**
 * Private data of pgsql_plugin
 */
struct private_pgsql_plugin_t {

	/**
	 * Public interface
	 */
	pgsql_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_pgsql_plugin_t *this)
{
	return "pgsql";
}

METHOD(plugin_t, get_features, int,
	private_pgsql_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(DATABASE, pgsql_database_create),
			PLUGIN_PROVIDE(DATABASE, DB_PGSQL),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_pgsql_plugin_t *this)
{
	pgsql_database_deinit();
	free(this);
}

/*
 * see header file
 */
PLUGIN_DEFINE(pgsql)
{
	private_pgsql_plugin_t *this;

	if (!pgsql_database_init())
	{
		DBG1(DBG_LIB, "PostgreSQL library initialization failed");
		return NULL;
	}

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}
