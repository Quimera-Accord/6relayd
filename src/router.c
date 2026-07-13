/**
 * Copyright (C) 2012-2013 Steven Barth <steven@midlink.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/route.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include "6relayd.h"
#include "list.h"
#include "router.h"

static void forward_router_solicitation(const struct relayd_interface *iface);
static void forward_router_advertisement(uint8_t *data, size_t len);
static int open_icmpv6_socket(struct icmp6_filter *filt, struct ipv6_mreq *slave_mreq);

static void handle_icmpv6(void *addr, void *data, size_t len, struct relayd_interface *iface);
static void send_router_advert(struct relayd_event *event);
static void schedule_solicited_advert(struct relayd_interface *iface);
static void sigusr1_refresh(int signal);

static struct relayd_event router_discovery_event = {-1, NULL, handle_icmpv6};

static FILE *fp_route = NULL;
static const struct relayd_config *config = NULL;
static bool in_shutdown = false;

int init_router_discovery_relay(const struct relayd_config *relayd_config) {
	config = relayd_config;

	// Filter ICMPv6 package types
	struct icmp6_filter filt;
	ICMP6_FILTER_SETBLOCKALL(&filt);
	ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filt);
	ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filt);

	// Open ICMPv6 socket
	struct ipv6_mreq slaves = {ALL_IPV6_ROUTERS, config->master.ifindex};
	router_discovery_event.socket = open_icmpv6_socket(&filt, &slaves);

	if (router_discovery_event.socket < 0) {
		syslog(LOG_ERR, "Failed to open RAW-socket: %s", strerror(errno));
		return -1;
	}

	if (!(fp_route = fopen("/proc/net/ipv6_route", "r"))) {
		syslog(LOG_ERR, "Failed to open routing table: %s", strerror(errno));
		return -1;
	}

	if (config->enable_router_discovery_server) {
		for (size_t i = 0; i < config->slavecount; ++i) {
			struct relayd_interface *iface = &config->slaves[i];
			iface->timer_rs.socket = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
			iface->timer_rs.handle_event = send_router_advert;

			if (iface->timer_rs.socket < 0) {
				syslog(LOG_ERR, "Failed to create timer: %s", strerror(errno));
				return -1;
			}

			relayd_register_event(&iface->timer_rs);
			send_router_advert(&iface->timer_rs);
		}

		// Disable looping for RA-events
		int zero = 0;
		setsockopt(router_discovery_event.socket, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &zero, sizeof(zero));

		// Get informed when addresses change
		struct sigaction sa = {.sa_handler = sigusr1_refresh};
		sigaction(SIGUSR1, &sa, NULL);
	} else if (config->enable_router_discovery_relay) {
		struct ipv6_mreq an = {ALL_IPV6_NODES, config->master.ifindex};
		setsockopt(router_discovery_event.socket, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &an, sizeof(an));
	}

	if (config->send_router_solicitation)
		forward_router_solicitation(&config->master);

	if (config->slavecount > 0 && (config->enable_router_discovery_relay || config->enable_router_discovery_server))
		relayd_register_event(&router_discovery_event);
	else
		close(router_discovery_event.socket);

	return 0;
}

void deinit_router_discovery_relay(void) {
	if (config->enable_router_discovery_server) {
		in_shutdown = true;
		for (size_t i = 0; i < config->slavecount; ++i)
			send_router_advert(&config->slaves[i].timer_rs);
	}
}

void router_invalidate_prefix(struct relayd_interface *iface, const struct in6_addr *addr, uint8_t prefixlen) {
	if (!config || !config->enable_router_discovery_server)
		return;

	// PIOs are always emitted as /64s elsewhere in this file (see
	// send_router_advert()); mirror that here rather than trying to
	// support arbitrary lengths in a one-off invalidation packet.
	if (prefixlen == 0 || prefixlen > 64)
		return;

	struct {
		struct nd_router_advert h;
		struct nd_opt_prefix_info prefix;
	} adv = {
		.h = {{.icmp6_type = ND_ROUTER_ADVERT, .icmp6_code = 0}, 0, 0},
	};

	struct nd_opt_prefix_info *p = &adv.prefix;
	memcpy(&p->nd_opt_pi_prefix, addr, 8);
	p->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
	p->nd_opt_pi_len = 4;
	p->nd_opt_pi_prefix_len = 64;
	p->nd_opt_pi_flags_reserved = 0;
	if (!config->ra_not_onlink)
		p->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_ONLINK;
	if (config->ra_managed_mode < RELAYD_MANAGED_NO_AFLAG)
		p->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_AUTO;
	p->nd_opt_pi_valid_time = 0;
	p->nd_opt_pi_preferred_time = 0;

	struct iovec iov = {&adv, sizeof(adv)};
	struct sockaddr_in6 all_nodes = {AF_INET6, 0, 0, ALL_IPV6_NODES, 0};
	relayd_forward_packet(router_discovery_event.socket, &all_nodes, &iov, 1, iface);

	char addrbuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, addr, addrbuf, sizeof(addrbuf));
	syslog(LOG_NOTICE, "Sent immediate RA invalidation (valid=0 preferred=0) for stale prefix %s/64 on %s", addrbuf, iface->ifname);
}

// Signal handler to resend all RDs
static void sigusr1_refresh(_unused int signal) {
	struct itimerspec its = {{0, 0}, {1, 0}};
	for (size_t i = 0; i < config->slavecount; ++i)
		timerfd_settime(config->slaves[i].timer_rs.socket, 0, &its, NULL);
}

// Create an ICMPv6 socket and setup basic attributes
static int open_icmpv6_socket(struct icmp6_filter *filt, struct ipv6_mreq *slave_mreq) {
	int sock = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
	if (sock < 0)
		return -1;

	// Let the kernel compute our checksums
	int val = 2;
	setsockopt(sock, IPPROTO_RAW, IPV6_CHECKSUM, &val, sizeof(val));

	// This is required by RFC 4861
	val = 255;
	setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val));
	setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &val, sizeof(val));

	// We need to know the source interface
	val = 1;
	setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val, sizeof(val));

	val = 0;
	setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &val, sizeof(val));

	// Filter ICMPv6 package types
	setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, filt, sizeof(*filt));

	// Configure multicast addresses
	for (size_t i = 0; i < config->slavecount; ++i) {
		slave_mreq->ipv6mr_interface = config->slaves[i].ifindex;
		setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, slave_mreq, sizeof(*slave_mreq));
	}

	return sock;
}

static time_t monotonic_time(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

// RFC 4861 §6.2.6: delay a solicited RA by a random 0..MAX_RA_DELAY_TIME
// (ms) to avoid several routers on the segment answering a Solicit in
// lockstep, and additionally make sure consecutive solicited RAs on the
// same interface are never sent less than MIN_DELAY_BETWEEN_RAS (s) apart
// -- if the previous RA (solicited or periodic) went out more recently
// than that, push the response out instead of sending it immediately.
//
// This reuses the same per-interface timerfd that the periodic
// unsolicited RA is scheduled on (iface->timer_rs): a Solicit only ever
// needs to make that timer fire *sooner*, never later, so if it's
// already armed for an earlier time than what this RS would require
// (e.g. the periodic RA was about to fire anyway), the existing timer is
// left alone.
static void schedule_solicited_advert(struct relayd_interface *iface) {
	uint32_t jitter_ms;
	relayd_urandom(&jitter_ms, sizeof(jitter_ms));
	jitter_ms %= (MAX_RA_DELAY_TIME + 1); // 0..MAX_RA_DELAY_TIME inclusive

	struct timespec delay = {0, (long)jitter_ms * 1000000L};

	time_t now = monotonic_time();
	time_t min_allowed = iface->ra_last_sent + MIN_DELAY_BETWEEN_RAS;
	if (iface->ra_last_sent != 0 && min_allowed > now)
		delay.tv_sec += min_allowed - now;

	struct itimerspec cur;
	if (!timerfd_gettime(iface->timer_rs.socket, &cur) && (cur.it_value.tv_sec != 0 || cur.it_value.tv_nsec != 0) &&
		(cur.it_value.tv_sec < delay.tv_sec || (cur.it_value.tv_sec == delay.tv_sec && cur.it_value.tv_nsec <= delay.tv_nsec))) {
		// A timer is already armed to fire at least as soon as what this
		// Solicit would require (typically the periodic unsolicited RA) --
		// leave it alone rather than pushing it out.
		return;
	}

	struct itimerspec val = {{0, 0}, delay};
	timerfd_settime(iface->timer_rs.socket, 0, &val, NULL);
}

// Event handler for incoming ICMPv6 packets
static void handle_icmpv6(_unused void *addr, void *data, size_t len, struct relayd_interface *iface) {
	struct icmp6_hdr *hdr = data;
	if (config->enable_router_discovery_server) { // Server mode
		if (hdr->icmp6_type == ND_ROUTER_SOLICIT && iface != &config->master)
			schedule_solicited_advert(iface);
	} else { // Relay mode
		if (hdr->icmp6_type == ND_ROUTER_ADVERT && iface == &config->master)
			forward_router_advertisement(data, len);
		else if (hdr->icmp6_type == ND_ROUTER_SOLICIT && iface != &config->master)
			forward_router_solicitation(&config->master);
	}
}

static bool match_route(const struct relayd_ipaddr *n, const struct in6_addr *addr) {
	if (n->prefix <= 32)
		return ntohl(n->addr.s6_addr32[0]) >> (32 - n->prefix) == ntohl(addr->s6_addr32[0]) >> (32 - n->prefix);

	if (n->addr.s6_addr32[0] != addr->s6_addr32[0])
		return false;

	return ntohl(n->addr.s6_addr32[1]) >> (64 - n->prefix) == ntohl(addr->s6_addr32[1]) >> (64 - n->prefix);
}

// Detect whether a default route exists, also find the source prefixes
static bool parse_routes(struct relayd_ipaddr *n, ssize_t len) {
	rewind(fp_route);

	char line[512], ifname[16];
	bool found_default = false;
	struct relayd_ipaddr p = {IN6ADDR_ANY_INIT, 0, 0, 0};
	while (fgets(line, sizeof(line), fp_route)) {
		uint32_t rflags;
		if (sscanf(line,
				"00000000000000000000000000000000 00 "
				"%*s %*s %*s %*s %*s %*s %*s %15s",
				ifname) &&
			strcmp(ifname, "lo")) {
			found_default = true;
		} else if (sscanf(line,
					   "%8" SCNx32 "%8" SCNx32 "%*8" SCNx32 "%*8" SCNx32 " %hhx %*s "
					   "%*s 00000000000000000000000000000000 %*s %*s %*s %" SCNx32 " lo",
					   &p.addr.s6_addr32[0], &p.addr.s6_addr32[1], &p.prefix, &rflags) &&
				   p.prefix > 0 && (rflags & RTF_NONEXTHOP) && (rflags & RTF_REJECT)) {
			// Find source prefixes by scanning through unreachable-routes
			p.addr.s6_addr32[0] = htonl(p.addr.s6_addr32[0]);
			p.addr.s6_addr32[1] = htonl(p.addr.s6_addr32[1]);

			for (ssize_t i = 0; i < len; ++i) {
				if (n[i].prefix <= 64 && n[i].prefix >= p.prefix && match_route(&p, &n[i].addr)) {
					n[i].prefix = p.prefix;
					break;
				}
			}
		}
	}

	return found_default;
}

// Router Advert server mode
static void send_router_advert(struct relayd_event *event) {
	uint64_t overrun;
	if (read(event->socket, &overrun, sizeof(overrun))) {
		// Make the compiler happy
	}

	struct relayd_interface *iface = container_of(event, struct relayd_interface, timer_rs);

	int mtu = relayd_get_interface_mtu(iface->ifname);
	if (mtu < 0)
		mtu = 1500;

	struct {
		struct nd_router_advert h;
		struct icmpv6_opt lladdr;
		struct nd_opt_mtu mtu;
		struct nd_opt_prefix_info prefix[RELAYD_MAX_PREFIXES];
	} adv = {
		.h = {{.icmp6_type = ND_ROUTER_ADVERT, .icmp6_code = 0}, 0, 0},
		.lladdr = {ND_OPT_SOURCE_LINKADDR, 1, {0}},
		.mtu = {ND_OPT_MTU, 1, 0, htonl(mtu)},
	};

	if (config->enable_dhcpv6_server) // Announce stateless DHCP
		adv.h.nd_ra_flags_reserved = ND_RA_FLAG_OTHER;

	if (config->ra_managed_mode >= RELAYD_MANAGED_MFLAG)
		adv.h.nd_ra_flags_reserved |= ND_RA_FLAG_MANAGED;

	if (config->ra_preference < 0)
		adv.h.nd_ra_flags_reserved |= ND_RA_PREF_LOW;
	else if (config->ra_preference > 0)
		adv.h.nd_ra_flags_reserved |= ND_RA_PREF_HIGH;
	relayd_get_interface_mac(iface->ifname, adv.lladdr.data);

	struct relayd_ipaddr addrs[RELAYD_MAX_PREFIXES];
	ssize_t ipcnt = 0;

	if (!in_shutdown) {
		ipcnt = relayd_get_interface_addresses(iface->ifindex, addrs, ARRAY_SIZE(addrs));

		if (parse_routes(addrs, ipcnt)) // Have default route
			adv.h.nd_ra_router_lifetime = htons(3 * MaxRtrAdvInterval);
	} else {
		// Final RA on shutdown: still fetch the prefixes/addresses we were
		// announcing, but force their valid/preferred lifetimes to 0 so we
		// emit explicit Prefix Information / Route Information Options
		// telling hosts and downstream routers to invalidate them right
		// away, instead of silently omitting the options and leaving
		// everyone to wait out the previous (up to 259200s) lifetime.
		// Router lifetime is intentionally left at 0 (its default here)
		// so we also immediately stop being treated as a default router.
		ipcnt = relayd_get_interface_addresses(iface->ifindex, addrs, ARRAY_SIZE(addrs));
		for (ssize_t i = 0; i < ipcnt; ++i) {
			addrs[i].preferred = 0;
			addrs[i].valid = 0;
		}
	}

	// Construct Prefix Information options
	bool have_public = false;
	size_t cnt = 0;

	for (ssize_t i = 0; i < ipcnt; ++i) {
		struct relayd_ipaddr *addr = &addrs[i];
		if (addr->prefix > 64)
			continue; // Address not suitable

		if (addr->preferred > MaxPreferredTime)
			addr->preferred = MaxPreferredTime;

		if (addr->valid > MaxValidTime)
			addr->valid = MaxValidTime;

		struct nd_opt_prefix_info *p = NULL;
		for (size_t i = 0; i < cnt; ++i) {
			if (!memcmp(&adv.prefix[i].nd_opt_pi_prefix, &addr->addr, 8))
				p = &adv.prefix[i];
		}

		if (!p) {
			if (cnt >= ARRAY_SIZE(adv.prefix))
				break;

			p = &adv.prefix[cnt++];
		}

		if ((addr->addr.s6_addr[0] & 0xfe) != 0xfc && addr->preferred > 0)
			have_public = true;

		memcpy(&p->nd_opt_pi_prefix, &addr->addr, 8);
		p->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
		p->nd_opt_pi_len = 4;
		p->nd_opt_pi_prefix_len = 64;
		p->nd_opt_pi_flags_reserved = 0;
		if (!config->ra_not_onlink)
			p->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_ONLINK;
		if (config->ra_managed_mode < RELAYD_MANAGED_NO_AFLAG)
			p->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_AUTO;
		p->nd_opt_pi_valid_time = htonl(addr->valid);
		p->nd_opt_pi_preferred_time = htonl(addr->preferred);
	}

	if (!have_public && !config->always_announce_default_router && adv.h.nd_ra_router_lifetime) {
		syslog(LOG_WARNING,
			"A default route is present but there is no public prefix "
			"on %s thus we don't announce a default route!",
			iface->ifname);
		adv.h.nd_ra_router_lifetime = 0;
	}

	if (have_public && config->deprecate_ula_if_public_avail)
		for (size_t i = 0; i < cnt; ++i)
			if ((adv.prefix[i].nd_opt_pi_prefix.s6_addr[0] & 0xfe) == 0xfc)
				adv.prefix[i].nd_opt_pi_preferred_time = 0;

	size_t routes_cnt = 0;
	struct {
		uint8_t type;
		uint8_t len;
		uint8_t prefix;
		uint8_t flags;
		uint32_t lifetime;
		uint32_t addr[2];
	} routes[RELAYD_MAX_PREFIXES];

	for (ssize_t i = 0; i < ipcnt; ++i) {
		struct relayd_ipaddr *addr = &addrs[i];
		if (addr->prefix > 64 || addr->prefix == 0) {
			continue; // Address not suitable
		} else if (addr->prefix > 32) {
			addr->addr.s6_addr32[1] &= htonl(~((1U << (64 - addr->prefix)) - 1));
		} else if (addr->prefix <= 32) {
			addr->addr.s6_addr32[0] &= htonl(~((1U << (32 - addr->prefix)) - 1));
			addr->addr.s6_addr32[1] = 0;
		}

		routes[routes_cnt].type = ND_OPT_ROUTE_INFO;
		routes[routes_cnt].len = sizeof(*routes) / 8;
		routes[routes_cnt].prefix = addr->prefix;
		routes[routes_cnt].flags = 0;
		if (config->ra_preference < 0)
			routes[routes_cnt].flags |= ND_RA_PREF_LOW;
		else if (config->ra_preference > 0)
			routes[routes_cnt].flags |= ND_RA_PREF_HIGH;
		routes[routes_cnt].lifetime = htonl(addr->valid);
		routes[routes_cnt].addr[0] = addr->addr.s6_addr32[0];
		routes[routes_cnt].addr[1] = addr->addr.s6_addr32[1];

		++routes_cnt;
	}

	// No DNS server is run on this box, so the RA carries only Prefix
	// Information (IA_PD-derived prefixes) and Route Information -- no
	// RDNSS/DNS Search List option is constructed or sent at all.
	struct iovec iov[] = {{&adv, (uint8_t *)&adv.prefix[cnt] - (uint8_t *)&adv}, {&routes, routes_cnt * sizeof(*routes)}};
	struct sockaddr_in6 all_nodes = {AF_INET6, 0, 0, ALL_IPV6_NODES, 0};
	relayd_forward_packet(router_discovery_event.socket, &all_nodes, iov, 2, iface);
	iface->ra_last_sent = monotonic_time();

	// Rearm timer
	struct itimerspec val = {{0, 0}, {0, 0}};
	relayd_urandom(&val.it_value.tv_sec, sizeof(val.it_value.tv_sec));
	val.it_value.tv_sec = (llabs(val.it_value.tv_sec) % (MaxRtrAdvInterval - MinRtrAdvInterval)) + MinRtrAdvInterval;
	timerfd_settime(event->socket, 0, &val, NULL);
}

// Forward router solicitation
static void forward_router_solicitation(const struct relayd_interface *iface) {
	struct icmp6_hdr rs = {ND_ROUTER_SOLICIT, 0, 0, {{0}}};
	struct iovec iov = {&rs, sizeof(rs)};
	struct sockaddr_in6 all_routers = {AF_INET6, 0, 0, ALL_IPV6_ROUTERS, iface->ifindex};

	syslog(LOG_NOTICE, "Sending RS to %s", iface->ifname);
	relayd_forward_packet(router_discovery_event.socket, &all_routers, &iov, 1, iface);
}

// Handler for incoming router solicitations on slave interfaces
static void forward_router_advertisement(uint8_t *data, size_t len) {
	struct nd_router_advert *adv = (struct nd_router_advert *)data;

	// Rewrite options
	uint8_t *end = data + len;
	uint8_t *mac_ptr = NULL;
	struct in6_addr *dns_ptr = NULL;
	size_t dns_count = 0;

	struct icmpv6_opt *opt;
	icmpv6_for_each_option(opt, &adv[1], end) {
		if (opt->type == ND_OPT_SOURCE_LINKADDR) {
			// Store address of source MAC-address
			mac_ptr = opt->data;
		} else if (opt->type == ND_OPT_RECURSIVE_DNS && opt->len > 1) {
			// Check if we have to rewrite DNS
			dns_ptr = (struct in6_addr *)&opt->data[6];
			dns_count = (opt->len - 1) / 2;
		}
	}

	syslog(LOG_NOTICE, "Got a RA");

	if (config->enable_dhcpv6_server) // Announce stateless DHCP
		adv->nd_ra_flags_reserved |= ND_RA_FLAG_OTHER;

	// Indicate a proxy, however we don't follow the rest of RFC 4389 yet
	adv->nd_ra_flags_reserved |= ND_RA_FLAG_PROXY;

	// Forward advertisement to all slave interfaces
	struct sockaddr_in6 all_nodes = {AF_INET6, 0, 0, ALL_IPV6_NODES, 0};
	struct iovec iov = {data, len};
	for (size_t i = 0; i < config->slavecount; ++i) {
		// Fixup source hardware address option
		if (mac_ptr)
			memcpy(mac_ptr, config->slaves[i].mac, 6);

		// If we have to rewrite DNS entries
		if (config->always_rewrite_dns && dns_ptr && dns_count > 0) {
			const struct in6_addr *rewrite;
			struct relayd_ipaddr addr;

			if (!IN6_IS_ADDR_UNSPECIFIED(&config->dnsaddr)) {
				rewrite = &config->dnsaddr;
			} else {
				if (relayd_get_interface_addresses(config->slaves[i].ifindex, &addr, 1) < 1)
					continue; // Unable to comply
				rewrite = &addr.addr;
			}

			// Copy over any other addresses
			for (size_t i = 0; i < dns_count; ++i)
				dns_ptr[i] = *rewrite;
		}

		relayd_forward_packet(router_discovery_event.socket, &all_nodes, &iov, 1, &config->slaves[i]);
	}
}
