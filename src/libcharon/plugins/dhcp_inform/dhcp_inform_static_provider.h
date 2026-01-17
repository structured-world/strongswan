/*
 * Copyright (C) 2025 Structured World Foundation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

/**
 * @defgroup dhcp_inform_static_provider dhcp_inform_static_provider
 * @{ @ingroup dhcp_inform
 */

#ifndef DHCP_INFORM_STATIC_PROVIDER_H_
#define DHCP_INFORM_STATIC_PROVIDER_H_

#include "dhcp_inform_provider.h"

typedef struct dhcp_inform_static_provider_t dhcp_inform_static_provider_t;

/**
 * Static route provider - reads routes from strongswan.conf.
 *
 * Supports:
 * - Global routes (apply to all clients)
 * - Per-pool routes (override global for clients in specific CIDR)
 *
 * Configuration example:
 *   charon.plugins.dhcp-inform.routes.route1 = 10.0.0.0/8
 *   charon.plugins.dhcp-inform.pools.prod.cidr = 10.100.0.0/16
 *   charon.plugins.dhcp-inform.pools.prod.routes.r1 = 192.168.1.0/24
 */
struct dhcp_inform_static_provider_t {

	/**
	 * Implements dhcp_inform_provider_t interface
	 */
	dhcp_inform_provider_t provider;
};

/**
 * Create static route provider.
 *
 * @return				provider instance, NULL on failure
 */
dhcp_inform_static_provider_t *dhcp_inform_static_provider_create();

#endif /** DHCP_INFORM_STATIC_PROVIDER_H_ @}*/
