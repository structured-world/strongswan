/*
 * Copyright (C) 2025 Lantec / ULA Software
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

/**
 * @defgroup dhcp_inform_p dhcp_inform
 * @ingroup cplugins
 *
 * @defgroup dhcp_inform_plugin dhcp_inform_plugin
 * @{ @ingroup dhcp_inform_p
 */

#ifndef DHCP_INFORM_PLUGIN_H_
#define DHCP_INFORM_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct dhcp_inform_plugin_t dhcp_inform_plugin_t;

/**
 * Plugin responding to DHCPINFORM with routes from PostgreSQL database.
 *
 * Windows VPN clients send DHCPINFORM after IKEv2 connection to get
 * split-tunnel routes via DHCP option 249 (Microsoft Classless Static Routes).
 *
 * This plugin:
 * - Listens for DHCPINFORM on the VPN interface
 * - Looks up the client's identity via their virtual IP
 * - Queries PostgreSQL for INTERNAL_IP4_SUBNET attributes (type 13)
 * - Responds with DHCPACK containing option 121/249 with routes
 */
struct dhcp_inform_plugin_t {

	/**
	 * Implements plugin_t interface.
	 */
	plugin_t plugin;
};

#endif /** DHCP_INFORM_PLUGIN_H_ @}*/
