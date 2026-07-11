/**
 * pd-sniffer.h
 *
 * See pd-sniffer.c for details.
 *
 * Replaces the old pd-lease-watcher.c (ISC dhclient lease-file watcher):
 * instead of watching a lease file on disk for changes (inotify + text
 * parsing, latency bounded by when/how often dhclient rewrites the file),
 * this sniffs DHCPv6 REPLY packets directly off the WAN (master) interface
 * as they arrive and reacts immediately, independent of dhclient's own
 * lease-file writing behavior/timing.
 *
 * TODO: hardcoded to a single (master, slave) pair for now -- same as the
 * old watcher. Generalize if we ever need to watch more than one WAN
 * uplink.
 */

#pragma once

struct relayd_interface;

// If true, pd-sniffer parses and logs everything it sees (prefixes found,
// address it would configure, on shutdown the address it would remove)
// but performs none of the actual side effects: no RTM_NEWADDR/RTM_DELADDR
// netlink calls, and iface->pd_addr_pending[]/pd_reconf/pd_watcher_managed
// are left untouched, so downstream DHCPv6-PD/NA clients and RAs are
// completely unaffected. Meant for verifying "is this actually seeing and
// parsing the ISP's REPLY correctly" via syslog before trusting it to
// apply anything for real. Off by default.
extern bool pd_sniffer_dry_run;

// wan_iface: the interface to sniff DHCPv6 traffic on (the PD requester's
// WAN link, e.g. ppp0 -- in practice always config.master).
// target_slave: the interface to apply the delegated prefix to (e.g. br0).
// Always also configures a /64 on-link address (EUI-64 host part, derived
// from target_slave's own MAC) on target_slave for the first /64 of every
// prefix applied -- required so that relayd_get_interface_addresses()
// (used by router.c to build RA Prefix Information Options) actually sees
// the delegated prefix; iface->pd_addr[] alone is invisible to that path.
//
// fallback_leasefile: optional (NULL to disable). Startup-only safety net,
// not a second permanent mode of operation: if the sniffer hasn't
// captured *any* REPLY within PD_SNIFFER_FALLBACK_SECS of this call (e.g.
// the ISP's REPLY happens to use an IPv6 extension header our BPF filter
// doesn't expect, or some other edge case we haven't hit yet), this file
// is read once, parsed as an ISC dhclient IPv6 lease file (same format
// pd-lease-watcher.c used to watch continuously), and its most recent
// iaprefix is applied exactly as if the sniffer itself had captured it.
// If the sniffer does capture a REPLY before the timer fires, the
// fallback read is cancelled and never happens. Either way, once past
// this startup window the sniffer is the only source from then on --
// the file is never watched or re-read again afterwards.
int init_pd_sniffer(struct relayd_interface *wan_iface, struct relayd_interface *target_slave, const char *fallback_leasefile);

// Called once on clean shutdown (SIGTERM/SIGHUP/SIGINT), *before* the
// process actually exits. No-op if init_pd_sniffer() was never called (-W
// not given). Removes the on-link kernel address we configured on
// target_slave, so the delegation doesn't linger there just because we
// stopped watching for it.
//
// POSSIBILITY (not implemented): on this same shutdown path we could also
// tear down target_slave itself (e.g. take br0 fully down) so nothing on
// the LAN side is left believing it still has a route through us. Left
// alone for now since that's a bigger behavior change than "stop
// advertising a stale prefix" and could have side effects on other things
// sharing br0 -- revisit deliberately if that's ever actually wanted.
void deinit_pd_sniffer(void);
