/*
 * Copyright (C) 2025 Lantec / ULA Software
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include "dhcp_inform_plugin.h"
#include "dhcp_inform_responder.h"

#include <daemon.h>
#include <plugins/plugin_feature.h>

typedef struct private_dhcp_inform_plugin_t private_dhcp_inform_plugin_t;

/**
 * Private data
 */
struct private_dhcp_inform_plugin_t {

	/**
	 * Public interface
	 */
	dhcp_inform_plugin_t public;

	/**
	 * DHCP INFORM responder
	 */
	dhcp_inform_responder_t *responder;
};

METHOD(plugin_t, get_name, char*,
	private_dhcp_inform_plugin_t *this)
{
	return "dhcp-inform";
}

/**
 * Register plugin features
 */
static bool plugin_cb(private_dhcp_inform_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		this->responder = dhcp_inform_responder_create();
		if (!this->responder)
		{
			return FALSE;
		}
	}
	else
	{
		DESTROY_IF(this->responder);
		this->responder = NULL;
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_dhcp_inform_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "dhcp-inform"),
				PLUGIN_DEPENDS(DATABASE, DB_PGSQL),
				PLUGIN_SDEPEND(CUSTOM, "attr-sql"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_dhcp_inform_plugin_t *this)
{
	free(this);
}

/*
 * Create plugin instance
 */
plugin_t *dhcp_inform_plugin_create()
{
	private_dhcp_inform_plugin_t *this;

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
