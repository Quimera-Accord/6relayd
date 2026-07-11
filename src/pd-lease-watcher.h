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
