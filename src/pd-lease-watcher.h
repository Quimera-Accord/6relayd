/**
 * pd-lease-watcher.h
 *
 * See pd-lease-watcher.c for details.
 *
 * TODO: hardcoded to a single (leasefile, slave) pair for now. Generalize
 * to a list of watchers, keyed by slave interface name, when we need to
 * watch more than one PD source (e.g. multiple WAN uplinks).
 */

#pragma once

struct relayd_interface;

// If true (default), the watcher also configures a /64 on-link address
// (host part ::1) on target_slave for the first /64 of every prefix it
// applies. This is required so that relayd_get_interface_addresses()
// (used by router.c to build RA Prefix Information Options) actually
// sees the delegated prefix -- iface->pd_addr[] alone is invisible to
// that path. Disable only if something else is already responsible for
// addressing target_slave.
extern bool pd_watcher_auto_address;

int init_pd_lease_watcher(const char *leasefile, struct relayd_interface *target_slave);

// Called once on clean shutdown (SIGTERM/SIGHUP/SIGINT), *before* the
// process actually exits. No-op if init_pd_lease_watcher() was never
// called (-w not given). Mirrors what pd_watcher_parse_and_apply() does
// when it sees the delegated prefix change to a *different* one: send an
// explicit RA invalidation (valid=0 preferred=0) for the currently-applied
// prefix and remove the on-link kernel address we configured for it, so
// the old delegation doesn't linger on the LAN or on target_slave just
// because we stopped watching it.
void deinit_pd_lease_watcher(void);
