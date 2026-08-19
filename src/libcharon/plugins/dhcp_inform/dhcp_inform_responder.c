/*
 * Copyright (C) 2025 Structured World Foundation
 *
 * DHCP Inform Responder - responds to Windows DHCPINFORM with routes.
 *
 * Receives over a plain UDP socket bound to port 67: the kernel delivers
 * datagrams there after IP processing, so DHCPINFORM works both off the
 * wire and as xfrm-decapsulated tunnel payload from road-warrior clients
 * (a device-level packet socket never sees the tunnelled case).
 *
 * Route sources (in priority order):
 * 1. Traffic Selectors (EXCLUSIVE - when enabled, only TS routes are used)
 * 2. Database (if configured and available)
 * 3. Static configuration (from strongswan.conf)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include "dhcp_inform_responder.h"
#include "dhcp_inform_provider.h"
#include "dhcp_inform_ts_provider.h"
#include "dhcp_inform_db_provider.h"
#include "dhcp_inform_static_provider.h"

#include <daemon.h>
#include <collections/linked_list.h>

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>

/* DHCP constants */
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_MAGIC_COOKIE 0x63825363

/* DHCP message types */
#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK      5
#define DHCPNAK      6
#define DHCPRELEASE  7
#define DHCPINFORM   8

/* DHCP options */
#define DHCP_OPT_PAD           0
#define DHCP_OPT_SUBNET_MASK   1
#define DHCP_OPT_ROUTER        3
#define DHCP_OPT_DNS_SERVER    6
#define DHCP_OPT_HOST_NAME     12
#define DHCP_OPT_REQUESTED_IP  50
#define DHCP_OPT_MESSAGE_TYPE  53
#define DHCP_OPT_SERVER_ID     54
#define DHCP_OPT_PARAM_LIST    55
#define DHCP_OPT_VENDOR_CLASS  60
#define DHCP_OPT_CLIENT_ID     61
#define DHCP_OPT_CLASSLESS_ROUTES     121  /* RFC 3442 */
#define DHCP_OPT_MS_CLASSLESS_ROUTES  249  /* Microsoft */
#define DHCP_OPT_END           255

/* Minimum DHCP message size (excluding options): op through magic = 236 bytes + 4 for options */
#define DHCP_MIN_MSG_SIZE      240

/* DHCP packet structure */
typedef struct __attribute__((packed)) {
	uint8_t op;           /* Message opcode */
	uint8_t htype;        /* Hardware type */
	uint8_t hlen;         /* Hardware address length */
	uint8_t hops;         /* Hops */
	uint32_t xid;         /* Transaction ID */
	uint16_t secs;        /* Seconds elapsed */
	uint16_t flags;       /* Flags */
	uint32_t ciaddr;      /* Client IP address */
	uint32_t yiaddr;      /* Your IP address */
	uint32_t siaddr;      /* Server IP address */
	uint32_t giaddr;      /* Gateway IP address */
	uint8_t chaddr[16];   /* Client hardware address */
	uint8_t sname[64];    /* Server name */
	uint8_t file[128];    /* Boot filename */
	uint32_t magic;       /* Magic cookie */
	uint8_t options[308]; /* Options (576 min packet - 236 fixed - 20 IP - 8 UDP - 4 margin) */
} dhcp_packet_t;

typedef struct private_dhcp_inform_responder_t private_dhcp_inform_responder_t;

/**
 * Private data
 */
struct private_dhcp_inform_responder_t {

	/**
	 * Public interface
	 */
	dhcp_inform_responder_t public;

	/**
	 * Traffic Selector route provider (EXCLUSIVE mode)
	 */
	dhcp_inform_ts_provider_t *ts_provider;

	/**
	 * Database route provider (optional)
	 */
	dhcp_inform_db_provider_t *db_provider;

	/**
	 * Static route provider (from config)
	 */
	dhcp_inform_static_provider_t *static_provider;

	/**
	 * UDP socket bound to the DHCP server port, used both to receive
	 * DHCPINFORM and to send the DHCPACK reply
	 */
	int fd;

	/**
	 * VPN interface name (socket is bound to it when configured)
	 */
	char *iface;

	/**
	 * Server IP address (on VPN interface)
	 */
	uint32_t server_ip;

	/**
	 * Source address for DHCPACK replies, defaults to the server address
	 */
	uint32_t source_ip;

	/**
	 * DNS server to advertise
	 */
	uint32_t dns_server;
};

/**
 * Check if traffic selector already exists in list (deduplication)
 */
static bool route_exists_in_list(linked_list_t *list, traffic_selector_t *ts)
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
 * Find the IKE identity of the peer holding the given virtual IP.
 * Returns a clone the caller must destroy, NULL if no IKE_SA matches.
 */
static identification_t *find_identity_by_vip(uint32_t vip_addr)
{
	identification_t *identity = NULL;
	enumerator_t *enumerator;
	ike_sa_t *ike_sa;
	host_t *vip;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = vip_addr,
	};

	vip = host_create_from_sockaddr((sockaddr_t*)&addr);
	if (!vip)
	{
		return NULL;
	}

	/* wait = FALSE: the manager's wait for a checked-out IKE_SA is
	 * unbounded and the enumerator visits every SA, so waiting would let
	 * a single SA stuck in a long operation anywhere on the daemon stall
	 * all DHCP service. Skipping a busy SA at worst costs this exchange
	 * its identity routes; the client's next INFORM refreshes them. */
	enumerator = charon->controller->create_ike_sa_enumerator(
						charon->controller, FALSE);
	while (!identity && enumerator->enumerate(enumerator, &ike_sa))
	{
		enumerator_t *vip_enum;
		host_t *ike_vip;

		vip_enum = ike_sa->create_virtual_ip_enumerator(ike_sa, FALSE);
		while (vip_enum->enumerate(vip_enum, &ike_vip))
		{
			if (vip->ip_equals(vip, ike_vip))
			{
				/* prefer the authenticated EAP identity, it falls back to
				 * the IKE identity for non-EAP peers; clone it, the
				 * identification_t is owned by the IKE_SA and only valid
				 * while the enumerator holds it */
				identity = ike_sa->get_other_eap_id(ike_sa);
				identity = identity->clone(identity);
				break;
			}
		}
		vip_enum->destroy(vip_enum);
	}
	enumerator->destroy(enumerator);
	vip->destroy(vip);

	return identity;
}

/**
 * Add routes from provider to list with deduplication
 */
static void add_routes_from_provider(dhcp_inform_provider_t *provider,
									 const char *client_ip,
									 identification_t *identity,
									 linked_list_t *routes)
{
	linked_list_t *provider_routes;
	enumerator_t *enumerator;
	traffic_selector_t *ts;
	int added = 0;
	int duplicates = 0;

	if (!provider || !provider->is_available(provider))
	{
		return;
	}

	provider_routes = provider->get_routes(provider, client_ip, identity);
	if (!provider_routes)
	{
		return;
	}

	/* Transfer ownership: routes go to target list or get destroyed if duplicate.
	 * After this loop, provider_routes list is empty of responsibility. */
	enumerator = provider_routes->create_enumerator(provider_routes);
	while (enumerator->enumerate(enumerator, &ts))
	{
		if (!ts)
		{
			/* Skip NULL entries that may result from failed clone operations */
			continue;
		}
		if (route_exists_in_list(routes, ts))
		{
			duplicates++;
			ts->destroy(ts);  /* Duplicate - destroy immediately */
		}
		else
		{
			routes->insert_last(routes, ts);  /* Transfer ownership to target */
			added++;
		}
	}
	enumerator->destroy(enumerator);

	/* Destroy list structure only - elements already handled above */
	provider_routes->destroy(provider_routes);

	if (added > 0 || duplicates > 0)
	{
		DBG2(DBG_NET, "dhcp-inform: %s provider added %d routes (%d duplicates)",
			 provider->get_name(provider), added, duplicates);
	}
}

/**
 * Get routes for client using available providers.
 *
 * PRIORITY-BASED ROUTE SELECTION (first available wins):
 * 1. TS routes - when use_ts_routes=yes, traffic selectors from IKE SA
 * 2. DB routes - when database configured, routes from SQL database
 * 3. Static routes - fallback to config routes with per-pool overrides
 *
 * Only ONE source is used per request. Multiple sources can be configured
 * for graceful fallback - highest-priority available source is selected.
 */
static linked_list_t *get_routes_for_client(private_dhcp_inform_responder_t *this,
											const char *client_ip,
											uint32_t ciaddr)
{
	linked_list_t *routes;
	dhcp_inform_provider_t *ts_prov, *db_prov, *static_prov;

	routes = linked_list_create();
	if (!routes)
	{
		DBG1(DBG_NET, "dhcp-inform: CRITICAL - failed to allocate routes list");
		return NULL;
	}

	if (!client_ip || !*client_ip)
	{
		DBG1(DBG_NET, "dhcp-inform: CORRUPTED DATA - empty client IP");
		return routes;
	}

	DBG1(DBG_NET, "dhcp-inform: looking up routes for IP %s", client_ip);

	/* Get provider interfaces */
	ts_prov = this->ts_provider ?
			  &this->ts_provider->provider : NULL;
	db_prov = this->db_provider ?
			  &this->db_provider->provider : NULL;
	static_prov = this->static_provider ?
				  &this->static_provider->provider : NULL;

	/* MODE 1: TS routes (exclusive) */
	if (ts_prov && ts_prov->is_available(ts_prov))
	{
		DBG1(DBG_NET, "dhcp-inform: using TS routes mode (exclusive)");
		add_routes_from_provider(ts_prov, client_ip, NULL, routes);
		DBG1(DBG_NET, "dhcp-inform: found %d routes from TS for %s",
			 routes->get_count(routes), client_ip);
		return routes;
	}

	/* MODE 2: Database routes (exclusive) */
	if (db_prov && db_prov->is_available(db_prov))
	{
		identification_t *identity;

		DBG1(DBG_NET, "dhcp-inform: using database routes mode (exclusive)");
		/* The SA scan runs only here: the database provider is the sole
		 * identity consumer, this branch means it is the selected route
		 * source, and a pool-only schema without v_user_routes never pays
		 * for a lookup it cannot use */
		identity = NULL;
		if (this->db_provider->uses_identity(this->db_provider))
		{
			identity = find_identity_by_vip(ciaddr);
		}
		if (identity)
		{
			DBG1(DBG_NET, "dhcp-inform: client %s identified as %Y",
				 client_ip, identity);
		}
		else
		{
			DBG2(DBG_NET, "dhcp-inform: no IKE_SA found for client %s",
				 client_ip);
		}
		add_routes_from_provider(db_prov, client_ip, identity, routes);
		DESTROY_IF(identity);
		DBG1(DBG_NET, "dhcp-inform: found %d routes from DB for %s",
			 routes->get_count(routes), client_ip);
		return routes;
	}

	/* MODE 3: Static routes with per-pool overrides (exclusive) */
	if (static_prov && static_prov->is_available(static_prov))
	{
		DBG1(DBG_NET, "dhcp-inform: using static routes mode (exclusive)");
		add_routes_from_provider(static_prov, client_ip, NULL, routes);
		DBG1(DBG_NET, "dhcp-inform: found %d routes from config for %s",
			 routes->get_count(routes), client_ip);
		return routes;
	}

	DBG1(DBG_NET, "dhcp-inform: no route provider available for %s", client_ip);
	return routes;
}

/**
 * Encode routes as DHCP option 121/249 format, truncating at max_len so the
 * result always fits the space the caller has left for both option copies
 */
static chunk_t encode_classless_routes(linked_list_t *routes, uint32_t gateway,
									   size_t max_len)
{
	chunk_t encoded;
	enumerator_t *enumerator;
	traffic_selector_t *ts;
	uint8_t *ptr;
	size_t total_len = 0;
	size_t route_len;

	enumerator = routes->create_enumerator(routes);
	while (enumerator->enumerate(enumerator, &ts))
	{
		host_t *net;
		uint8_t prefix;

		/* options 121/249 are IPv4-only; providers filter families, this
		 * guards against any selector slipping through (e.g. from TS mode) */
		if (ts->get_type(ts) != TS_IPV4_ADDR_RANGE)
		{
			continue;
		}

		ts->to_subnet(ts, &net, &prefix);
		net->destroy(net);
		route_len = 1 + ((prefix + 7) / 8) + 4;
		if (total_len + route_len > max_len)
		{
			DBG1(DBG_NET, "dhcp-inform: truncating routes to the %zu bytes "
				 "the DHCP options can carry", max_len);
			break;
		}
		total_len += route_len;
	}
	enumerator->destroy(enumerator);

	if (total_len == 0)
	{
		return chunk_empty;
	}

	encoded = chunk_alloc(total_len);
	if (!encoded.ptr)
	{
		DBG1(DBG_NET, "dhcp-inform: failed to allocate routes buffer");
		return chunk_empty;
	}
	ptr = encoded.ptr;

	uint8_t *ptr_end = encoded.ptr + encoded.len;
	enumerator = routes->create_enumerator(routes);
	while (enumerator->enumerate(enumerator, &ts))
	{
		host_t *net;
		chunk_t net_chunk;
		uint8_t prefix;
		int subnet_bytes;

		if (ts->get_type(ts) != TS_IPV4_ADDR_RANGE)
		{
			continue;
		}

		ts->to_subnet(ts, &net, &prefix);
		net_chunk = net->get_address(net);
		subnet_bytes = (prefix + 7) / 8;

		/* Bounds check: 1 (prefix) + subnet_bytes + 4 (gateway) */
		if (ptr + 1 + subnet_bytes + 4 > ptr_end)
		{
			net->destroy(net);
			break;
		}

		*ptr++ = prefix;

		if (subnet_bytes > 0 && net_chunk.len >= (size_t)subnet_bytes)
		{
			memcpy(ptr, net_chunk.ptr, subnet_bytes);
			ptr += subnet_bytes;
		}

		memcpy(ptr, &gateway, 4);
		ptr += 4;

		net->destroy(net);
	}
	enumerator->destroy(enumerator);

	/* Adjust actual length if we stopped early */
	encoded.len = ptr - encoded.ptr;

	return encoded;
}

/**
 * Find DHCP option in packet, parsing only the actually received bytes:
 * clients commonly send the 300-byte BOOTP minimum, less than the full
 * options capacity of dhcp_packet_t
 */
static uint8_t *find_dhcp_option(dhcp_packet_t *pkt, size_t pkt_len,
								 uint8_t code, uint8_t *len)
{
	uint8_t *opt = pkt->options;
	uint8_t *end = (uint8_t*)pkt + min(pkt_len, sizeof(*pkt));

	while (opt < end && *opt != DHCP_OPT_END)
	{
		if (*opt == DHCP_OPT_PAD)
		{
			opt++;
			continue;
		}
		if (opt + 1 >= end)
		{
			break;
		}
		if (*opt == code)
		{
			/* reject options whose payload extends past the received data */
			if (opt + 2 + opt[1] > end)
			{
				break;
			}
			if (len)
			{
				*len = opt[1];
			}
			return opt + 2;
		}
		/* Bounds check before advancing */
		if (opt + 2 + opt[1] > end)
		{
			break;
		}
		opt += 2 + opt[1];
	}
	return NULL;
}

/**
 * Get DHCP message type, 0 unless the option carries exactly one byte
 */
static uint8_t get_dhcp_type(dhcp_packet_t *pkt, size_t pkt_len)
{
	uint8_t *type, type_len = 0;

	type = find_dhcp_option(pkt, pkt_len, DHCP_OPT_MESSAGE_TYPE, &type_len);
	return (type && type_len == 1) ? *type : 0;
}

/**
 * Send DHCPACK response, unicast to the client's address over the same
 * UDP socket the request arrived on; the kernel routes it back through
 * the IPsec policy like any other datagram
 */
static void send_dhcp_ack(private_dhcp_inform_responder_t *this,
						  dhcp_packet_t *request, linked_list_t *routes,
						  uint32_t client_ip)
{
	dhcp_packet_t ack;
	uint8_t *opt;
	uint8_t *opt_end;
	chunk_t routes_encoded = chunk_empty;
	struct sockaddr_in dest;
	size_t ack_len;
	size_t required_space;
	size_t routes_max;

	memset(&ack, 0, sizeof(ack));

	/* Build DHCP response */
	ack.op = 2;  /* BOOTREPLY */
	ack.htype = request->htype;
	ack.hlen = request->hlen;
	ack.xid = request->xid;
	ack.ciaddr = client_ip;
	/* RFC 2131 4.3.5: an ACK answering INFORM assigns nothing, so yiaddr
	 * stays zero, and siaddr names a bootstrap next-server, not us: the
	 * server identity travels in option 54 only */
	memcpy(ack.chaddr, request->chaddr, 16);
	ack.magic = htonl(DHCP_MAGIC_COOKIE);

	opt = ack.options;
	opt_end = ack.options + sizeof(ack.options);

	/* Message Type = DHCPACK */
	*opt++ = DHCP_OPT_MESSAGE_TYPE;
	*opt++ = 1;
	*opt++ = DHCPACK;

	/* Server Identifier */
	*opt++ = DHCP_OPT_SERVER_ID;
	*opt++ = 4;
	memcpy(opt, &this->server_ip, 4);
	opt += 4;

	/* DNS Server */
	if (this->dns_server)
	{
		*opt++ = DHCP_OPT_DNS_SERVER;
		*opt++ = 4;
		memcpy(opt, &this->dns_server, 4);
		opt += 4;
	}

	/* Encode routes with server_ip as gateway, capped to the space that
	 * remains for TWO option copies (2-byte headers each) plus END, and to
	 * the 255-byte single-option maximum */
	if (opt + 5 < opt_end)
	{
		routes_max = min((size_t)(opt_end - opt - 5) / 2, (size_t)255);
	}
	else
	{
		routes_max = 0;
	}
	routes_encoded = encode_classless_routes(routes, this->server_ip,
											 routes_max);

	if (routes_encoded.len > 0)
	{
		/* Calculate required space: 2 options * (2 byte header + data) + END */
		required_space = 2 * (2 + routes_encoded.len) + 1;

		if (opt + required_space <= opt_end)
		{
			/* Option 121 - RFC 3442 */
			*opt++ = DHCP_OPT_CLASSLESS_ROUTES;
			*opt++ = routes_encoded.len;
			memcpy(opt, routes_encoded.ptr, routes_encoded.len);
			opt += routes_encoded.len;

			/* Option 249 - Microsoft */
			*opt++ = DHCP_OPT_MS_CLASSLESS_ROUTES;
			*opt++ = routes_encoded.len;
			memcpy(opt, routes_encoded.ptr, routes_encoded.len);
			opt += routes_encoded.len;
		}
		else
		{
			DBG1(DBG_NET, "dhcp-inform: routes too large for options buffer "
				 "(%zu bytes needed, %zu available)", required_space,
				 (size_t)(opt_end - opt));
		}
	}

	/* Always free routes_encoded (chunk_free handles chunk_empty) */
	chunk_free(&routes_encoded);

	if (opt < opt_end)
	{
		*opt++ = DHCP_OPT_END;
	}
	else
	{
		DBG1(DBG_NET, "dhcp-inform: no space for END option in buffer");
		return;
	}

	/* Send only the used part of the message, never less than the
	 * 300-byte BOOTP minimum some clients insist on */
	ack_len = max((size_t)(opt - (uint8_t*)&ack), (size_t)300);

	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(DHCP_CLIENT_PORT);
	dest.sin_addr.s_addr = client_ip;

	/* Pin the reply source via IP_PKTINFO: an unconnected socket would
	 * take it from the route, which can disagree with the DHCP server
	 * identifier and miss the IPsec policy */
	struct iovec iov = {
		.iov_base = &ack,
		.iov_len = ack_len,
	};
	char cbuf[CMSG_SPACE(sizeof(struct in_pktinfo))] = {};
	struct msghdr msg = {
		.msg_name = &dest,
		.msg_namelen = sizeof(dest),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
	};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	struct in_pktinfo *pktinfo;

	cmsg->cmsg_level = IPPROTO_IP;
	cmsg->cmsg_type = IP_PKTINFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
	pktinfo = (struct in_pktinfo*)CMSG_DATA(cmsg);
	pktinfo->ipi_spec_dst.s_addr = this->source_ip;

	if (sendmsg(this->fd, &msg, 0) < 0)
	{
		/* never fall back to a route-selected source: a reply from an
		 * address outside the negotiated traffic selectors misses the
		 * IPsec policy and would disclose the route set in clear text */
		DBG1(DBG_NET, "dhcp-inform: failed to send DHCPACK from pinned "
			 "source: %s", strerror(errno));
	}
	else
	{
		char ip_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &client_ip, ip_str, sizeof(ip_str));
		DBG1(DBG_NET, "dhcp-inform: sent DHCPACK to %s with %d routes",
			 ip_str, routes->get_count(routes));
	}
}

/**
 * Process a received DHCP message (UDP payload, IP/UDP headers already
 * stripped by the kernel)
 */
static void process_dhcp_packet(private_dhcp_inform_responder_t *this,
								dhcp_packet_t *dhcp, size_t len)
{
	linked_list_t *routes;
	char client_ip_str[INET_ADDRSTRLEN];

	if (len < DHCP_MIN_MSG_SIZE)
	{
		return;
	}

	/* Verify magic cookie */
	if (ntohl(dhcp->magic) != DHCP_MAGIC_COOKIE)
	{
		return;
	}

	/* Only BOOTREQUEST */
	if (dhcp->op != 1)
	{
		return;
	}

	/* Only DHCPINFORM, which carries the client's address in ciaddr */
	if (get_dhcp_type(dhcp, len) != DHCPINFORM || !dhcp->ciaddr)
	{
		return;
	}

	/* Convert client IP to string (thread-safe) */
	inet_ntop(AF_INET, &dhcp->ciaddr, client_ip_str, sizeof(client_ip_str));
	DBG1(DBG_NET, "dhcp-inform: received DHCPINFORM from %s", client_ip_str);

	/* Get routes from providers (mutually exclusive: TS OR DB OR static);
	 * the identity lookup happens inside, only for the mode that uses it */
	routes = get_routes_for_client(this, client_ip_str, dhcp->ciaddr);

	if (!routes)
	{
		DBG1(DBG_NET, "dhcp-inform: CRITICAL - failed to get routes list for %s",
			 client_ip_str);
		return;
	}

	if (routes->get_count(routes) > 0)
	{
		DBG1(DBG_NET, "dhcp-inform: sending DHCPACK with %d routes",
			 routes->get_count(routes));
		send_dhcp_ack(this, dhcp, routes, dhcp->ciaddr);
	}
	else
	{
		DBG1(DBG_NET, "dhcp-inform: no routes found for %s", client_ip_str);
	}

	routes->destroy_offset(routes, offsetof(traffic_selector_t, destroy));
}

/**
 * Watcher callback for the DHCP socket
 */
CALLBACK(receive_dhcp, bool,
	private_dhcp_inform_responder_t *this, int fd, watcher_event_t event)
{
	dhcp_packet_t packet;
	struct sockaddr_in src;
	socklen_t src_len = sizeof(src);
	ssize_t len;

	/* Zero so option parsing never walks uninitialized tail bytes when the
	 * client sends less than the full options capacity */
	memset(&packet, 0, sizeof(packet));

	len = recvfrom(fd, &packet, sizeof(packet), MSG_DONTWAIT,
				   (struct sockaddr*)&src, &src_len);

	if (len < 0)
	{
		if (errno != EAGAIN && errno != EWOULDBLOCK)
		{
			DBG1(DBG_NET, "dhcp-inform: recvfrom failed: %s", strerror(errno));
		}
		return TRUE;
	}

	/* Trust ciaddr only when it matches the actual sender: the wildcard
	 * bind is reachable beyond the VPN, and a spoofed ciaddr would
	 * otherwise trigger SA scans, database queries and misdirected ACKs */
	if (src_len < sizeof(src) || src.sin_family != AF_INET ||
		src.sin_port != htons(DHCP_CLIENT_PORT) ||
		(len >= (ssize_t)DHCP_MIN_MSG_SIZE &&
		 src.sin_addr.s_addr != packet.ciaddr))
	{
		char src_str[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &src.sin_addr, src_str, sizeof(src_str));
		DBG2(DBG_NET, "dhcp-inform: dropping datagram with unexpected "
			 "sender %s:%u", src_str, ntohs(src.sin_port));
		return TRUE;
	}

	process_dhcp_packet(this, &packet, len);

	return TRUE;
}

/**
 * Create the UDP socket receiving DHCPINFORM and sending replies.
 * Returns the socket, or the negated errno of the failed operation.
 */
static int create_dhcp_socket(const char *iface)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(DHCP_SERVER_PORT),
		.sin_addr.s_addr = htonl(INADDR_ANY),
	};
	int fd, err, on = 1;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (fd < 0)
	{
		DBG1(DBG_NET, "dhcp-inform: failed to create socket: %s",
			 strerror(errno));
		return -errno;
	}

	/* The port is owned exclusively, without any address reuse: for UDP,
	 * SO_REUSEADDR/SO_REUSEPORT would let this bind slip next to an
	 * existing DHCP daemon and divert its unicast traffic. UDP has no
	 * TIME_WAIT, so nothing is needed for restart handling either; when
	 * another daemon owns the port, bind fails with EADDRINUSE and the
	 * responder starts disabled. */

	/* DHCPINFORM is typically sent to 255.255.255.255 */
	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0)
	{
		DBG1(DBG_NET, "dhcp-inform: failed to set SO_BROADCAST: %s",
			 strerror(errno));
		err = errno;
		close(fd);
		return -err;
	}

	/* Optional: restrict to the VPN interface. Tunnelled packets are still
	 * delivered, they surface on the interface carrying the ESP traffic.
	 * The binding applies to the whole socket, so ACKs also egress here:
	 * an rx-only device filter does not exist for UDP, and a second port-67
	 * send socket would need address reuse, reopening the flow-diversion
	 * hole that exclusive ownership closes. Asymmetrically routed gateways
	 * should leave the option unset and let routing pick the egress. */
	if (iface && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface,
							strlen(iface)) < 0)
	{
		DBG1(DBG_NET, "dhcp-inform: failed to bind to %s: %s",
			 iface, strerror(errno));
		err = errno;
		close(fd);
		return -err;
	}

	if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		DBG1(DBG_NET, "dhcp-inform: failed to bind to port 67: %s",
			 strerror(errno));
		err = errno;
		close(fd);
		return -err;
	}

	return fd;
}

METHOD(dhcp_inform_responder_t, destroy, void,
	private_dhcp_inform_responder_t *this)
{
	if (this->fd >= 0)
	{
		lib->watcher->remove(lib->watcher, this->fd);
		close(this->fd);
	}

	/* Destroy providers */
	if (this->ts_provider)
	{
		this->ts_provider->provider.destroy(&this->ts_provider->provider);
	}
	if (this->db_provider)
	{
		this->db_provider->provider.destroy(&this->db_provider->provider);
	}
	if (this->static_provider)
	{
		this->static_provider->provider.destroy(&this->static_provider->provider);
	}

	free(this->iface);
	free(this);
}

/**
 * Check whether an IPv4 address is configured on the host by binding an
 * ephemeral UDP socket to it
 */
static bool address_is_local(uint32_t addr)
{
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = addr,
	};
	int fd, ret;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
	{
		/* cannot probe, do not warn on a guess */
		return TRUE;
	}
	ret = bind(fd, (struct sockaddr*)&sin, sizeof(sin));
	close(fd);
	return ret == 0;
}

/**
 * See header
 */
dhcp_inform_responder_t *dhcp_inform_responder_create()
{
	private_dhcp_inform_responder_t *this;
	char *iface, *server_ip, *dns_server, *source_ip;
	bool has_routes = FALSE;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.fd = -1,
	);

	/* Get configuration */
	iface = lib->settings->get_str(lib->settings,
		"%s.plugins.dhcp-inform.interface", NULL, lib->ns);
	server_ip = lib->settings->get_str(lib->settings,
		"%s.plugins.dhcp-inform.server", NULL, lib->ns);
	dns_server = lib->settings->get_str(lib->settings,
		"%s.plugins.dhcp-inform.dns", NULL, lib->ns);
	source_ip = lib->settings->get_str(lib->settings,
		"%s.plugins.dhcp-inform.source_address", NULL, lib->ns);

	if (!server_ip)
	{
		DBG1(DBG_NET, "dhcp-inform: missing server config");
		destroy(this);
		return NULL;
	}

	/* Initialize route providers */
	this->ts_provider = dhcp_inform_ts_provider_create();
	this->db_provider = dhcp_inform_db_provider_create();
	this->static_provider = dhcp_inform_static_provider_create();

	/* Check if any provider is available */
	if (this->ts_provider &&
		this->ts_provider->provider.is_available(&this->ts_provider->provider))
	{
		DBG1(DBG_NET, "dhcp-inform: TS provider enabled (EXCLUSIVE mode)");
		has_routes = TRUE;
	}
	if (this->db_provider &&
		this->db_provider->provider.is_available(&this->db_provider->provider))
	{
		DBG1(DBG_NET, "dhcp-inform: database provider enabled");
		has_routes = TRUE;
	}
	if (this->static_provider &&
		this->static_provider->provider.is_available(&this->static_provider->provider))
	{
		DBG1(DBG_NET, "dhcp-inform: static provider enabled");
		has_routes = TRUE;
	}

	if (!has_routes)
	{
		DBG1(DBG_NET, "dhcp-inform: no route sources configured, plugin disabled");
		destroy(this);
		return NULL;
	}

	/* Parse server IP */
	if (inet_pton(AF_INET, server_ip, &this->server_ip) != 1)
	{
		DBG1(DBG_NET, "dhcp-inform: invalid server IP: %s", server_ip);
		destroy(this);
		return NULL;
	}

	/* Parse the reply source, defaults to the server address; an empty
	 * value means unset */
	if (source_ip && *source_ip)
	{
		if (inet_pton(AF_INET, source_ip, &this->source_ip) != 1)
		{
			DBG1(DBG_NET, "dhcp-inform: invalid source address: %s",
				 source_ip);
			destroy(this);
			return NULL;
		}
	}
	else
	{
		this->source_ip = this->server_ip;
	}
	if (this->source_ip == INADDR_ANY)
	{
		/* a zero ipi_spec_dst places no constraint on the source and
		 * would reopen the route-selected cleartext path */
		DBG1(DBG_NET, "dhcp-inform: reply source cannot be 0.0.0.0");
		destroy(this);
		return NULL;
	}
	if (!address_is_local(this->source_ip))
	{
		char buf[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &this->source_ip, buf, sizeof(buf));
		/* not fatal: a floating HA address may only arrive on promotion,
		 * and the source is applied per packet, not at bind time */
		DBG1(DBG_NET, "dhcp-inform: reply source %s is not configured on "
			 "any interface, DHCPACKs will fail until it appears", buf);
	}

	/* Parse DNS server */
	if (dns_server)
	{
		if (inet_pton(AF_INET, dns_server, &this->dns_server) != 1)
		{
			DBG1(DBG_NET, "dhcp-inform: invalid DNS server IP: %s", dns_server);
			destroy(this);
			return NULL;
		}
	}

	if (iface)
	{
		this->iface = strdup(iface);
		if (!this->iface)
		{
			DBG1(DBG_NET, "dhcp-inform: failed to duplicate interface name");
			destroy(this);
			return NULL;
		}
	}

	/* Create the UDP socket used for both directions */
	this->fd = create_dhcp_socket(iface);
	if (this->fd == -EADDRINUSE)
	{
		/* another DHCP daemon owns the port without SO_REUSEPORT; keep the
		 * daemon running with the responder disabled instead of failing the
		 * whole charon startup on such hosts */
		DBG1(DBG_NET, "dhcp-inform: port 67 is taken by another process, "
			 "responder disabled");
		return &this->public;
	}
	if (this->fd < 0)
	{
		destroy(this);
		return NULL;
	}

	/* Warm the FQDN cache only now: construction cannot fail anymore, so
	 * the queued background jobs cannot outlive the provider they use.
	 * The database enumeration below is synchronous and must finish before
	 * the watcher can dispatch an INFORM: SQLite in multi-thread builds
	 * forbids concurrent use of one connection and the driver only locks
	 * for serialized builds. DNS warming stays asynchronous: an INFORM
	 * racing the first resolutions at worst gets an ACK without an FQDN
	 * route, and the client's next periodic INFORM fills it in; delaying
	 * the ACK instead would risk the client's retransmit timeout, losing
	 * ALL routes for that exchange. */
	if (this->db_provider)
	{
		this->db_provider->prewarm(this->db_provider);
	}

	/* Register with watcher */
	lib->watcher->add(lib->watcher, this->fd, WATCHER_READ,
					  receive_dhcp, this);

	DBG1(DBG_NET, "dhcp-inform: responder started on %s (%s)",
		 iface ?: "all", server_ip);

	return &this->public;
}
