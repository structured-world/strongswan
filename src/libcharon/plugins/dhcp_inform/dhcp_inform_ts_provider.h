/*
 * Copyright (C) 2025 Structured World Foundation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

/**
 * @defgroup dhcp_inform_ts_provider dhcp_inform_ts_provider
 * @{ @ingroup dhcp_inform
 */

#ifndef DHCP_INFORM_TS_PROVIDER_H_
#define DHCP_INFORM_TS_PROVIDER_H_

#include "dhcp_inform_provider.h"

typedef struct dhcp_inform_ts_provider_t dhcp_inform_ts_provider_t;

/**
 * Traffic Selector route provider - extracts routes from IKE SA.
 *
 * This provider is EXCLUSIVE - when enabled, it's the only source of routes.
 * Designed for Windows 7 compatibility where clients don't properly handle
 * traffic selectors pushed via IKE.
 *
 * Behavior:
 * - Finds IKE SA by matching client virtual IP
 * - Extracts remote traffic selectors from all CHILD_SAs
 * - Converts traffic selectors to routes for DHCP Option 121/249
 */
struct dhcp_inform_ts_provider_t {

	/**
	 * Implements dhcp_inform_provider_t interface
	 */
	dhcp_inform_provider_t provider;
};

/**
 * Create TS route provider.
 *
 * @return				provider instance, NULL on failure
 */
dhcp_inform_ts_provider_t *dhcp_inform_ts_provider_create();

#endif /** DHCP_INFORM_TS_PROVIDER_H_ @}*/
