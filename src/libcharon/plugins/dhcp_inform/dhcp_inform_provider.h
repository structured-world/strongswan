/*
 * Copyright (C) 2025 Structured World Foundation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

/**
 * @defgroup dhcp_inform_provider dhcp_inform_provider
 * @{ @ingroup dhcp_inform
 */

#ifndef DHCP_INFORM_PROVIDER_H_
#define DHCP_INFORM_PROVIDER_H_

#include <collections/linked_list.h>

typedef struct dhcp_inform_provider_t dhcp_inform_provider_t;

/**
 * Route provider interface for DHCP INFORM plugin.
 *
 * Implementations provide routes from different sources:
 * - Database (pgsql/mysql/sqlite)
 * - Static configuration
 * - IKE Traffic Selectors
 */
struct dhcp_inform_provider_t {

	/**
	 * Get routes for a client by virtual IP.
	 *
	 * @param client_ip		client's virtual IP address string
	 * @return				linked_list_t of traffic_selector_t (caller destroys),
	 *						or NULL on error
	 */
	linked_list_t* (*get_routes)(dhcp_inform_provider_t *this,
								 const char *client_ip);

	/**
	 * Get provider name for logging.
	 *
	 * @return				provider name string (static, do not free)
	 */
	const char* (*get_name)(dhcp_inform_provider_t *this);

	/**
	 * Check if provider is available/configured.
	 *
	 * @return				TRUE if provider can provide routes
	 */
	bool (*is_available)(dhcp_inform_provider_t *this);

	/**
	 * Destroy provider instance.
	 */
	void (*destroy)(dhcp_inform_provider_t *this);
};

#endif /** DHCP_INFORM_PROVIDER_H_ @}*/
