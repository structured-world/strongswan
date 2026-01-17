/*
 * Copyright (C) 2025 Structured World Foundation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

/**
 * @defgroup dhcp_inform dhcp_inform
 * @ingroup cplugins
 *
 * @defgroup dhcp_inform_plugin dhcp_inform_plugin
 * @{ @ingroup dhcp_inform
 */

#ifndef DHCP_INFORM_PLUGIN_H_
#define DHCP_INFORM_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct dhcp_inform_plugin_t dhcp_inform_plugin_t;

/**
 * Plugin responding to DHCPINFORM with split-tunnel routes.
 *
 * Windows VPN clients send DHCPINFORM after IKEv2 connection to get
 * split-tunnel routes via DHCP option 121/249.
 *
 * Route sources (in priority order):
 * 1. Traffic Selectors - EXCLUSIVE mode (for Windows 7 compatibility)
 * 2. Database (PostgreSQL/MySQL/SQLite) - if configured
 * 3. Static configuration from strongswan.conf
 *
 * The plugin works WITHOUT any database when using static or TS routes.
 */
struct dhcp_inform_plugin_t {

	/**
	 * Implements plugin_t interface.
	 */
	plugin_t plugin;
};

#endif /** DHCP_INFORM_PLUGIN_H_ @}*/
