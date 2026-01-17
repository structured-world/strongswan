/*
 * Copyright (C) 2025 Structured World Foundation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include "dhcp_inform_ts_provider.h"

#include <daemon.h>
#include <collections/linked_list.h>
#include <sa/ike_sa.h>
#include <sa/child_sa.h>
#include <selectors/traffic_selector.h>
#include <networking/host.h>

typedef struct private_dhcp_inform_ts_provider_t private_dhcp_inform_ts_provider_t;

/**
 * Private data
 */
struct private_dhcp_inform_ts_provider_t {

	/**
	 * Public interface
	 */
	dhcp_inform_ts_provider_t public;

	/**
	 * Whether TS routes are enabled
	 */
	bool enabled;
};

/**
 * Check if a traffic selector is a valid route (not 0.0.0.0/0)
 */
static bool is_valid_route_ts(traffic_selector_t *ts)
{
	host_t *net;
	uint8_t mask;

	if (ts->get_type(ts) != TS_IPV4_ADDR_RANGE)
	{
		/* Only handle IPv4 for DHCP option 121/249 */
		return FALSE;
	}

	/* Convert to subnet to get the mask */
	if (!ts->to_subnet(ts, &net, &mask))
	{
		/* Not a valid subnet */
		return FALSE;
	}
	net->destroy(net);

	/* Skip default route (0.0.0.0/0) - we don't want to push that */
	if (mask == 0)
	{
		return FALSE;
	}

	return TRUE;
}

/**
 * Check if traffic selector already exists in list (deduplication)
 */
static bool ts_exists_in_list(linked_list_t *list, traffic_selector_t *ts)
{
	enumerator_t *enumerator;
	traffic_selector_t *existing;
	bool found = FALSE;

	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, &existing))
	{
		if (ts->equals(ts, existing))
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);

	return found;
}

/**
 * Find IKE SA by virtual IP and extract traffic selectors
 */
static linked_list_t *extract_ts_from_ike_sa(const char *client_ip)
{
	linked_list_t *routes;
	enumerator_t *ike_enum, *child_enum, *ts_enum;
	ike_sa_t *ike_sa;
	child_sa_t *child_sa;
	traffic_selector_t *ts;
	host_t *client_vip;
	bool found_sa = FALSE;
	int route_count = 0;

	routes = linked_list_create();

	if (!client_ip)
	{
		DBG1(DBG_CFG, "dhcp-inform-ts: no client IP provided");
		return routes;
	}

	client_vip = host_create_from_string((char*)client_ip, 0);
	if (!client_vip)
	{
		DBG1(DBG_CFG, "dhcp-inform-ts: invalid client IP: %s", client_ip);
		return routes;
	}

	/* Enumerate all IKE SAs to find one matching this client */
	ike_enum = charon->ike_sa_manager->create_enumerator(
										charon->ike_sa_manager, TRUE);

	while (ike_enum->enumerate(ike_enum, &ike_sa))
	{
		enumerator_t *vip_enum;
		host_t *vip;
		bool match = FALSE;

		/* Check if any virtual IP of this IKE SA matches our client */
		vip_enum = ike_sa->create_virtual_ip_enumerator(ike_sa, FALSE);
		while (vip_enum->enumerate(vip_enum, &vip))
		{
			if (vip->ip_equals(vip, client_vip))
			{
				match = TRUE;
				break;
			}
		}
		vip_enum->destroy(vip_enum);

		if (!match)
		{
			continue;
		}

		found_sa = TRUE;
		DBG1(DBG_CFG, "dhcp-inform-ts: found IKE SA for client %s", client_ip);

		/* Enumerate CHILD SAs and extract remote traffic selectors */
		child_enum = ike_sa->create_child_sa_enumerator(ike_sa);
		while (child_enum->enumerate(child_enum, &child_sa))
		{
			/* Get remote (server-side) traffic selectors - these are the
			 * networks the client should be able to reach */
			ts_enum = child_sa->create_ts_enumerator(child_sa, FALSE);
			while (ts_enum->enumerate(ts_enum, &ts))
			{
				if (is_valid_route_ts(ts) && !ts_exists_in_list(routes, ts))
				{
					routes->insert_last(routes, ts->clone(ts));
					route_count++;
					DBG2(DBG_CFG, "dhcp-inform-ts: extracted route %R", ts);
				}
			}
			ts_enum->destroy(ts_enum);
		}
		child_enum->destroy(child_enum);

		/* Found the SA, no need to continue */
		break;
	}
	ike_enum->destroy(ike_enum);
	client_vip->destroy(client_vip);

	if (!found_sa)
	{
		DBG1(DBG_CFG, "dhcp-inform-ts: no IKE SA found for client %s",
			 client_ip);
	}
	else
	{
		DBG1(DBG_CFG, "dhcp-inform-ts: extracted %d routes for client %s",
			 route_count, client_ip);
	}

	return routes;
}

METHOD(dhcp_inform_provider_t, get_routes, linked_list_t*,
	private_dhcp_inform_ts_provider_t *this, const char *client_ip)
{
	if (!this->enabled)
	{
		return linked_list_create();
	}

	return extract_ts_from_ike_sa(client_ip);
}

METHOD(dhcp_inform_provider_t, get_name, const char*,
	private_dhcp_inform_ts_provider_t *this)
{
	return "traffic-selectors";
}

METHOD(dhcp_inform_provider_t, is_available, bool,
	private_dhcp_inform_ts_provider_t *this)
{
	return this->enabled;
}

METHOD(dhcp_inform_provider_t, destroy, void,
	private_dhcp_inform_ts_provider_t *this)
{
	free(this);
}

/**
 * See header
 */
dhcp_inform_ts_provider_t *dhcp_inform_ts_provider_create()
{
	private_dhcp_inform_ts_provider_t *this;

	INIT(this,
		.public = {
			.provider = {
				.get_routes = _get_routes,
				.get_name = _get_name,
				.is_available = _is_available,
				.destroy = _destroy,
			},
		},
		.enabled = lib->settings->get_bool(lib->settings,
			"%s.plugins.dhcp-inform.use_ts_routes", FALSE, lib->ns),
	);

	if (this->enabled)
	{
		DBG1(DBG_CFG, "dhcp-inform: TS route provider enabled (EXCLUSIVE mode)");
	}
	else
	{
		DBG2(DBG_CFG, "dhcp-inform: TS route provider disabled");
	}

	return &this->public;
}
