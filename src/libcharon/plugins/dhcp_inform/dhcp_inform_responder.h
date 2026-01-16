/*
 * Copyright (C) 2025 Structured World Foundation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

/**
 * @defgroup dhcp_inform_responder dhcp_inform_responder
 * @{ @ingroup dhcp_inform_p
 */

#ifndef DHCP_INFORM_RESPONDER_H_
#define DHCP_INFORM_RESPONDER_H_

typedef struct dhcp_inform_responder_t dhcp_inform_responder_t;

/**
 * DHCPINFORM responder that sends routes from database.
 */
struct dhcp_inform_responder_t {

	/**
	 * Destroy the responder.
	 */
	void (*destroy)(dhcp_inform_responder_t *this);
};

/**
 * Create a DHCP INFORM responder instance.
 *
 * @return			responder instance, NULL on failure
 */
dhcp_inform_responder_t *dhcp_inform_responder_create();

#endif /** DHCP_INFORM_RESPONDER_H_ @}*/
