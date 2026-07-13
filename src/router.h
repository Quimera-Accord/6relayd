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

#pragma once
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <stdint.h>

struct relayd_interface;

// Immediately send a one-off RA to `iface` containing a single Prefix
// Information Option for `addr`/`prefixlen` with valid/preferred lifetimes
// forced to 0. Used when a delegated prefix changes out from under a
// running relay (e.g. pd-lease-watcher.c noticing the ISP handed out a new
// /56 after a ppp0 reconnect): removing the stale on-link kernel address
// only keeps it out of the *next* periodic RA, it does not retroactively
// tell hosts that already cached the old prefix (with its original,
// possibly multi-day lifetime) to drop it now. This is the "prefix changed
// while running" counterpart to deinit_router_discovery_relay()'s final
// RA on shutdown.
void router_invalidate_prefix(struct relayd_interface *iface, const struct in6_addr *addr, uint8_t prefixlen);

struct icmpv6_opt {
	uint8_t type;
	uint8_t len;
	uint8_t data[6];
};

#define icmpv6_for_each_option(opt, start, end) \
	for (opt = (struct icmpv6_opt *)(start); (void *)(opt + 1) <= (void *)(end) && opt->len > 0 && (void *)(opt + opt->len) <= (void *)(end); opt += opt->len)

#define MaxRtrAdvInterval 600
#define MinRtrAdvInterval (MaxRtrAdvInterval / 3)
#define MaxValidTime 7200
#define MaxPreferredTime (3 * MaxRtrAdvInterval)

// RFC 4861 §6.2.6: a solicited RA MUST be delayed by a random time
// between 0 and MAX_RA_DELAY_TIME (in ms) to avoid multiple routers
// answering a Router Solicitation in lockstep. In addition, consecutive
// solicited (multicast) RAs on the same interface MUST NOT be sent more
// often than once every MIN_DELAY_BETWEEN_RAS (in s) -- if a Solicit
// arrives sooner than that after the previous RA, the response must be
// pushed out to satisfy the minimum spacing instead of being dropped.
#define MAX_RA_DELAY_TIME 500
#define MIN_DELAY_BETWEEN_RAS 3

#define ND_RA_FLAG_PROXY 0x4
#define ND_RA_PREF_HIGH (1 << 3)
#define ND_RA_PREF_LOW (3 << 3)
