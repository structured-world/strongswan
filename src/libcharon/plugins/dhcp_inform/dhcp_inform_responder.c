/*
 * Copyright (C) 2025 Structured World Foundation
 *
 * DHCP Inform Responder - responds to Windows DHCPINFORM with routes from DB.
 * Uses packet socket like forecast plugin to catch broadcast from VPN tunnels.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include "dhcp_inform_responder.h"

#include <daemon.h>
#include <threading/thread.h>
#include <processing/jobs/callback_job.h>
#include <collections/linked_list.h>
#include <database/database.h>

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>

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

/* Standard IP TTL for locally-generated packets */
#define IP_DEFAULT_TTL         64

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
	 * Database connection
	 */
	database_t *db;

	/**
	 * Packet socket for receiving broadcasts (AF_PACKET)
	 */
	int pkt_fd;

	/**
	 * Raw socket for sending unicast responses (AF_INET, SOCK_RAW)
	 */
	int raw_fd;

	/**
	 * Interface index
	 */
	int ifindex;

	/**
	 * VPN interface name
	 */
	char *iface;

	/**
	 * Server IP address (on VPN interface)
	 */
	uint32_t server_ip;

	/**
	 * DNS server to advertise
	 */
	uint32_t dns_server;
};

/**
 * Parse CIDR notation with validation
 */
static traffic_selector_t *parse_cidr(const char *cidr)
{
	char *slash, *ip_str;
	int prefix = 32;
	host_t *host;
	traffic_selector_t *ts = NULL;

	if (!cidr || !*cidr)
	{
		DBG1(DBG_NET, "dhcp-inform: CORRUPTED DATA - empty CIDR");
		return NULL;
	}

	if (strlen(cidr) > 43)  /* max: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/128 */
	{
		DBG1(DBG_NET, "dhcp-inform: CORRUPTED DATA - CIDR too long: %.20s...", cidr);
		return NULL;
	}

	ip_str = strdup(cidr);
	if (!ip_str)
	{
		DBG1(DBG_NET, "dhcp-inform: memory allocation failed");
		return NULL;
	}

	slash = strchr(ip_str, '/');
	if (slash)
	{
		*slash = '\0';
		prefix = atoi(slash + 1);
		if (prefix < 0 || prefix > 32)
		{
			DBG1(DBG_NET, "dhcp-inform: CORRUPTED DATA - invalid prefix %d in %s", prefix, cidr);
			free(ip_str);
			return NULL;
		}
	}

	host = host_create_from_string(ip_str, 0);
	if (!host)
	{
		DBG1(DBG_NET, "dhcp-inform: CORRUPTED DATA - invalid IP in CIDR: %s", ip_str);
		free(ip_str);
		return NULL;
	}

	ts = traffic_selector_create_from_subnet(host, prefix, 0, 0, 65535);
	host->destroy(host);
	if (!ts)
	{
		DBG1(DBG_NET, "dhcp-inform: failed to create traffic selector for %s", cidr);
	}

	free(ip_str);
	return ts;
}

/**
 * Get routes from database by client virtual IP.
 * Looks up routes for the pool that contains this IP.
 */
static linked_list_t *get_routes_by_ip(private_dhcp_inform_responder_t *this,
									   const char *client_ip)
{
	linked_list_t *routes;
	enumerator_t *enumerator;
	char *route_value;
	int routes_parsed = 0;
	int routes_failed = 0;

	routes = linked_list_create();
	if (!routes)
	{
		DBG1(DBG_NET, "dhcp-inform: CRITICAL - failed to allocate routes list");
		return NULL;
	}

	if (!this->db)
	{
		DBG1(DBG_NET, "dhcp-inform: no database connection");
		return routes;
	}

	if (!client_ip || !*client_ip)
	{
		DBG1(DBG_NET, "dhcp-inform: CORRUPTED DATA - empty client IP");
		return routes;
	}

	DBG1(DBG_NET, "dhcp-inform: looking up routes for IP %s", client_ip);

	/* Query routes for the environment/pool that contains this IP
	 * Uses v_pool_routes VIEW: (pool_cidr, route)
	 * We check if client_ip falls within pool_cidr
	 */
	enumerator = this->db->query(this->db,
		"SELECT route FROM v_pool_routes WHERE ?::inet << pool_cidr::inet",
		DB_TEXT, client_ip,
		DB_TEXT);

	if (!enumerator)
	{
		DBG1(DBG_NET, "dhcp-inform: primary query failed, trying fallback");
		/* Fallback: get routes from auto_ip_pools directly */
		enumerator = this->db->query(this->db,
			"SELECT unnest(aip.routes) as route "
			"FROM auto_ip_pools aip "
			"JOIN environments e ON e.auto_ip_pool_id = aip.id "
			"WHERE e.is_active = true "
			"AND ?::inet << aip.cidr::inet",
			DB_TEXT, client_ip,
			DB_TEXT);
	}

	if (!enumerator)
	{
		DBG1(DBG_NET, "dhcp-inform: all queries failed for %s", client_ip);
		return routes;
	}

	while (enumerator->enumerate(enumerator, &route_value))
	{
		routes_parsed++;

		if (!route_value)
		{
			DBG1(DBG_NET, "dhcp-inform: CORRUPTED DATA - NULL route value at row %d", routes_parsed);
			routes_failed++;
			continue;
		}

		traffic_selector_t *ts = parse_cidr(route_value);
		if (ts)
		{
			routes->insert_last(routes, ts);
			DBG1(DBG_NET, "dhcp-inform: added route %s", route_value);
		}
		else
		{
			DBG1(DBG_NET, "dhcp-inform: CORRUPTED DATA - failed to parse route: %s", route_value);
			routes_failed++;
		}
	}
	enumerator->destroy(enumerator);

	if (routes_failed > 0)
	{
		DBG1(DBG_NET, "dhcp-inform: WARNING - %d/%d routes had corrupted data",
			 routes_failed, routes_parsed);
	}

	DBG1(DBG_NET, "dhcp-inform: found %d valid routes for %s",
		 routes->get_count(routes), client_ip);
	return routes;
}

/**
 * Encode routes as DHCP option 121/249 format
 */
static chunk_t encode_classless_routes(linked_list_t *routes, uint32_t gateway)
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

		ts->to_subnet(ts, &net, &prefix);
		net->destroy(net);
		route_len = 1 + ((prefix + 7) / 8) + 4;
		/* Check for overflow (max DHCP option is 255 bytes anyway) */
		if (total_len + route_len > 255)
		{
			DBG1(DBG_NET, "dhcp-inform: routes exceed maximum option size");
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
 * Find DHCP option in packet
 */
static uint8_t *find_dhcp_option(dhcp_packet_t *pkt, uint8_t code, uint8_t *len)
{
	uint8_t *opt = pkt->options;
	uint8_t *end = pkt->options + sizeof(pkt->options);

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
 * Get DHCP message type
 */
static uint8_t get_dhcp_type(dhcp_packet_t *pkt)
{
	uint8_t *type = find_dhcp_option(pkt, DHCP_OPT_MESSAGE_TYPE, NULL);
	return type ? *type : 0;
}

/**
 * Calculate IP checksum
 */
static uint16_t ip_checksum(void *data, size_t len)
{
	uint32_t sum = 0;
	uint16_t *ptr = data;

	while (len > 1)
	{
		sum += *ptr++;
		len -= 2;
	}
	if (len == 1)
	{
		sum += *(uint8_t*)ptr;
	}

	while (sum >> 16)
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	return ~sum;
}

/**
 * Calculate UDP checksum with pseudo-header
 */
static uint16_t udp_checksum(uint32_t src, uint32_t dst,
							 void *data, size_t len)
{
	uint32_t sum = 0;
	uint16_t *ptr;

	/* Pseudo-header */
	sum += (src >> 16) & 0xFFFF;
	sum += src & 0xFFFF;
	sum += (dst >> 16) & 0xFFFF;
	sum += dst & 0xFFFF;
	sum += htons(IPPROTO_UDP);
	sum += htons(len);

	/* UDP header + data */
	ptr = (uint16_t*)data;
	while (len > 1)
	{
		sum += *ptr++;
		len -= 2;
	}
	if (len == 1)
	{
		sum += *(uint8_t*)ptr;
	}

	while (sum >> 16)
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	return ~sum;
}

/**
 * IP ID counter for packet identification (atomic increment for thread safety)
 */
static uint32_t ip_id_counter = 0;

/**
 * Send DHCPACK response via raw socket
 */
static void send_dhcp_ack(private_dhcp_inform_responder_t *this,
						  dhcp_packet_t *request, linked_list_t *routes,
						  uint32_t client_ip)
{
	struct __attribute__((packed)) {
		struct iphdr ip;
		struct udphdr udp;
		dhcp_packet_t dhcp;
	} pkt;
	uint8_t *opt;
	uint8_t *opt_end;
	chunk_t routes_encoded = chunk_empty;
	struct sockaddr_in dest;
	size_t dhcp_len, udp_len, total_len;
	size_t required_space;

	memset(&pkt, 0, sizeof(pkt));

	/* Build DHCP response */
	pkt.dhcp.op = 2;  /* BOOTREPLY */
	pkt.dhcp.htype = request->htype;
	pkt.dhcp.hlen = request->hlen;
	pkt.dhcp.xid = request->xid;
	pkt.dhcp.ciaddr = client_ip;
	pkt.dhcp.yiaddr = client_ip;
	pkt.dhcp.siaddr = this->server_ip;
	memcpy(pkt.dhcp.chaddr, request->chaddr, 16);
	pkt.dhcp.magic = htonl(DHCP_MAGIC_COOKIE);

	opt = pkt.dhcp.options;
	opt_end = pkt.dhcp.options + sizeof(pkt.dhcp.options);

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

	/* Encode routes with server_ip as gateway */
	routes_encoded = encode_classless_routes(routes, this->server_ip);

	if (routes_encoded.len > 0 && routes_encoded.len <= 255)
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

	/* Calculate lengths */
	dhcp_len = sizeof(dhcp_packet_t);
	udp_len = sizeof(struct udphdr) + dhcp_len;
	total_len = sizeof(struct iphdr) + udp_len;

	/* Build IP header */
	pkt.ip.version = 4;
	pkt.ip.ihl = 5;
	pkt.ip.tos = 0;
	pkt.ip.tot_len = htons(total_len);
	pkt.ip.id = htons(__sync_fetch_and_add(&ip_id_counter, 1) & 0xFFFF);
	pkt.ip.frag_off = 0;
	pkt.ip.ttl = IP_DEFAULT_TTL;
	pkt.ip.protocol = IPPROTO_UDP;
	pkt.ip.saddr = this->server_ip;
	pkt.ip.daddr = client_ip;
	pkt.ip.check = 0;
	pkt.ip.check = ip_checksum(&pkt.ip, sizeof(pkt.ip));

	/* Build UDP header */
	pkt.udp.source = htons(DHCP_SERVER_PORT);
	pkt.udp.dest = htons(DHCP_CLIENT_PORT);
	pkt.udp.len = htons(udp_len);
	pkt.udp.check = 0;
	pkt.udp.check = udp_checksum(pkt.ip.saddr, pkt.ip.daddr, &pkt.udp, udp_len);

	/* Send via raw socket - routing handled by kernel policy */
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = client_ip;

	if (sendto(this->raw_fd, &pkt, total_len, 0,
			   (struct sockaddr*)&dest, sizeof(dest)) < 0)
	{
		DBG1(DBG_NET, "dhcp-inform: failed to send DHCPACK: %s", strerror(errno));
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
 * Process received DHCP packet
 */
static void process_dhcp_packet(private_dhcp_inform_responder_t *this,
								struct iphdr *ip, size_t len)
{
	struct udphdr *udp;
	dhcp_packet_t *dhcp;
	size_t ip_hdr_len, udp_len;
	uint8_t msg_type;
	linked_list_t *routes;
	char client_ip_str[INET_ADDRSTRLEN];

	if (len < sizeof(struct iphdr))
	{
		return;
	}

	/* Validate IP header length field (ihl is in 32-bit words, valid range 5-15) */
	if (ip->ihl < 5 || ip->ihl > 15)
	{
		return;
	}

	ip_hdr_len = ip->ihl * 4;
	if (len < ip_hdr_len + sizeof(struct udphdr))
	{
		return;
	}

	udp = (struct udphdr*)((uint8_t*)ip + ip_hdr_len);
	udp_len = ntohs(udp->len);

	if (ntohs(udp->dest) != DHCP_SERVER_PORT)
	{
		return;
	}

	if (udp_len < sizeof(struct udphdr) + DHCP_MIN_MSG_SIZE)
	{
		return;
	}

	/* Verify actual buffer has enough data for DHCP packet before accessing */
	if (len < ip_hdr_len + sizeof(struct udphdr) + sizeof(dhcp_packet_t))
	{
		return;
	}

	dhcp = (dhcp_packet_t*)((uint8_t*)udp + sizeof(struct udphdr));

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

	/* Only DHCPINFORM */
	msg_type = get_dhcp_type(dhcp);
	if (msg_type != DHCPINFORM)
	{
		return;
	}

	/* Convert client IP to string (thread-safe) */
	inet_ntop(AF_INET, &dhcp->ciaddr, client_ip_str, sizeof(client_ip_str));
	DBG1(DBG_NET, "dhcp-inform: received DHCPINFORM from %s", client_ip_str);

	/* Get routes from database by client IP */
	routes = get_routes_by_ip(this, client_ip_str);

	if (!routes)
	{
		DBG1(DBG_NET, "dhcp-inform: CRITICAL - failed to get routes list for %s",
			 client_ip_str);
		return;
	}

	if (routes->get_count(routes) > 0)
	{
		DBG1(DBG_NET, "dhcp-inform: sending DHCPACK with %d routes", routes->get_count(routes));
		send_dhcp_ack(this, dhcp, routes, dhcp->ciaddr);
	}
	else
	{
		DBG1(DBG_NET, "dhcp-inform: no routes found for %s", client_ip_str);
	}

	routes->destroy_offset(routes, offsetof(traffic_selector_t, destroy));
}

/**
 * Watcher callback for packet socket
 */
CALLBACK(receive_dhcp, bool,
	private_dhcp_inform_responder_t *this, int fd, watcher_event_t event)
{
	uint8_t buf[2048 + sizeof(struct iphdr)];
	struct iphdr *hdr = (struct iphdr*)buf;
	ssize_t len;
	struct sockaddr_ll addr;
	socklen_t alen = sizeof(addr);

	len = recvfrom(fd, buf, sizeof(buf), MSG_DONTWAIT,
				   (struct sockaddr*)&addr, &alen);

	if (len < 0)
	{
		if (errno != EAGAIN && errno != EWOULDBLOCK)
		{
			DBG1(DBG_NET, "dhcp-inform: recvfrom failed: %s", strerror(errno));
		}
		return TRUE;
	}

	if (len >= (ssize_t)sizeof(struct iphdr))
	{
		process_dhcp_packet(this, hdr, len);
	}

	return TRUE;
}

/**
 * Install BPF filter for DHCP broadcast packets
 */
static bool install_filter(private_dhcp_inform_responder_t *this)
{
	/* BPF filter:
	 * - IP protocol = UDP
	 * - UDP dest port = 67 (DHCP server)
	 * - Dest IP = broadcast (0xFFFFFFFF) or our subnet broadcast
	 */
	struct sock_filter filter_code[] = {
		/* Load IP protocol */
		BPF_STMT(BPF_LD+BPF_B+BPF_ABS, offsetof(struct iphdr, protocol)),
		/* Check if UDP (17) */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_UDP, 0, 7),
		/* Load IP header length */
		BPF_STMT(BPF_LDX+BPF_B+BPF_MSH, 0),
		/* Load UDP dest port (at IP header + 2) */
		BPF_STMT(BPF_LD+BPF_H+BPF_IND, 2),
		/* Check if port 67 */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, DHCP_SERVER_PORT, 0, 4),
		/* Load dest IP */
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct iphdr, daddr)),
		/* Check if broadcast 255.255.255.255 */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xFFFFFFFF, 1, 0),
		/* Also accept limited broadcast - reject */
		BPF_STMT(BPF_RET+BPF_K, 0),
		/* Accept packet */
		BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
		BPF_STMT(BPF_RET+BPF_A, 0),
	};
	struct sock_fprog filter = {
		.len = sizeof(filter_code) / sizeof(struct sock_filter),
		.filter = filter_code,
	};

	if (setsockopt(this->pkt_fd, SOL_SOCKET, SO_ATTACH_FILTER,
				   &filter, sizeof(filter)) < 0)
	{
		DBG1(DBG_NET, "dhcp-inform: failed to attach BPF filter: %s",
			 strerror(errno));
		return FALSE;
	}

	return TRUE;
}

/**
 * Get interface index
 */
static int get_ifindex(int fd, const char *ifname)
{
	struct ifreq ifr = {};

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
	ifr.ifr_name[IFNAMSIZ-1] = '\0';

	if (ioctl(fd, SIOCGIFINDEX, &ifr) == 0)
	{
		return ifr.ifr_ifindex;
	}
	return 0;
}

METHOD(dhcp_inform_responder_t, destroy, void,
	private_dhcp_inform_responder_t *this)
{
	if (this->pkt_fd >= 0)
	{
		lib->watcher->remove(lib->watcher, this->pkt_fd);
		close(this->pkt_fd);
	}
	if (this->raw_fd >= 0)
	{
		close(this->raw_fd);
	}
	DESTROY_IF(this->db);
	free(this->iface);
	free(this);
}

/**
 * See header
 */
dhcp_inform_responder_t *dhcp_inform_responder_create()
{
	private_dhcp_inform_responder_t *this;
	char *db_uri, *iface, *server_ip, *dns_server;
	int on = 1;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.pkt_fd = -1,
		.raw_fd = -1,
	);

	/* Get configuration */
	db_uri = lib->settings->get_str(lib->settings,
		"%s.plugins.dhcp-inform.database", NULL, lib->ns);
	iface = lib->settings->get_str(lib->settings,
		"%s.plugins.dhcp-inform.interface", NULL, lib->ns);
	server_ip = lib->settings->get_str(lib->settings,
		"%s.plugins.dhcp-inform.server", NULL, lib->ns);
	dns_server = lib->settings->get_str(lib->settings,
		"%s.plugins.dhcp-inform.dns", NULL, lib->ns);

	if (!db_uri || !server_ip)
	{
		DBG1(DBG_NET, "dhcp-inform: missing database or server config");
		destroy(this);
		return NULL;
	}

	/* Connect to database */
	this->db = lib->db->create(lib->db, db_uri);
	if (!this->db)
	{
		DBG1(DBG_NET, "dhcp-inform: failed to connect to database");
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

	/* Create packet socket for receiving broadcasts */
	this->pkt_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (this->pkt_fd < 0)
	{
		DBG1(DBG_NET, "dhcp-inform: failed to create packet socket: %s",
			 strerror(errno));
		destroy(this);
		return NULL;
	}

	/* Create raw socket for sending responses */
	this->raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (this->raw_fd < 0)
	{
		DBG1(DBG_NET, "dhcp-inform: failed to create raw socket: %s",
			 strerror(errno));
		destroy(this);
		return NULL;
	}

	/* Set IP_HDRINCL for raw socket */
	if (setsockopt(this->raw_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		DBG1(DBG_NET, "dhcp-inform: failed to set IP_HDRINCL: %s",
			 strerror(errno));
		destroy(this);
		return NULL;
	}

	/* Get interface index and bind packet socket */
	if (iface)
	{
		this->ifindex = get_ifindex(this->raw_fd, iface);
		if (!this->ifindex)
		{
			DBG1(DBG_NET, "dhcp-inform: failed to get interface index for %s",
				 iface);
			destroy(this);
			return NULL;
		}

		struct sockaddr_ll addr = {
			.sll_family = AF_PACKET,
			.sll_protocol = htons(ETH_P_IP),
			.sll_ifindex = this->ifindex,
		};
		if (bind(this->pkt_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
		{
			DBG1(DBG_NET, "dhcp-inform: failed to bind packet socket to %s: %s",
				 iface, strerror(errno));
			destroy(this);
			return NULL;
		}
	}

	/* Install BPF filter */
	if (!install_filter(this))
	{
		destroy(this);
		return NULL;
	}

	/* Register with watcher */
	lib->watcher->add(lib->watcher, this->pkt_fd, WATCHER_READ,
					  receive_dhcp, this);

	DBG1(DBG_NET, "dhcp-inform: responder started on %s", iface ?: "all");

	return &this->public;
}
