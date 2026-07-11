/**
 * pd-lease-watcher.c
 *
 * Watches an ISC dhclient IPv6 lease file (e.g. /var/dhcpcV6ppp0.leases)
 * for changes to the delegated "iaprefix" and injects that prefix directly
 * into a target slave interface's pd_addr[]/pd_addr_len, bypassing the
 * usual relayd_get_interface_addresses() (netlink) path entirely.
 *
 * TODO: currently hardcoded to a single target slave interface (br0).
 * Generalize to accept <leasefile>:<slave-ifname> pairs via CLI once we
 * need to watch more than one PD source/slave combination.
 *
 * Format we parse (ISC dhclient lease6 block), e.g.:
 *
 *   lease6 {
 *     interface "ppp0";
 *     ia-pd 00:00:00:00 {
 *       starts 1783722898;
 *       renew 86400;
 *       rebind 138240;
 *       iaprefix 2804:4600:292:6300::/56 {
 *         starts 1783722898;
 *         preferred-life 172800;
 *         max-life 259200;
 *       }
 *       option dhcp6.status-code success "Success";
 *     }
 *     ...
 *   }
 *
 * We only care about the "iaprefix <addr>/<len> {" line and the
 * preferred-life/max-life values immediately following it.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "6relayd.h"
#include "pd-lease-watcher.h"

bool pd_watcher_auto_address = true;

// Same clock basis dhcpv6-ia.c's monotonic_time() uses (CLOCK_MONOTONIC),
// so that iface->pd_addr_applied_at is directly comparable against the
// 'now' computed there. Kept local/duplicated rather than exported from
// dhcpv6-ia.c to avoid widening that file's internal-only interface.
static long pd_watcher_monotonic_time(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

#define PD_WATCHER_INOTIFY_BUF_SIZE (16 * (sizeof(struct inotify_event) + NAME_MAX + 1))

// Prefix retirement policy: downstream is now exclusively DHCPv6-PD/NA
// (SLAAC is disabled on the requesting router, e.g. a MikroTik configured
// with a DHCPv6-Client that pulls both its address and the delegated
// prefix and manages its own routing from that). There are therefore no
// SLAAC-derived addresses/routes on the LAN side that need an explicit
// valid=0/preferred=0 RA to be told to go away, and no need to physically
// force-remove the previous on-link address on br0 either: when the
// delegated prefix changes we simply apply the new address (a genuinely
// different IPv6 address, since the host part is now derived from br0's
// own EUI-64 rather than a fixed ::1 -- see pd_watcher_set_slave_address()),
// and let the old address coast out on the lifetime it already has. The
// kernel expires and removes it on its own; we never call RTM_DELADDR for
// this case. The previous "gradual decay" state machine (shortened
// lifetime + scheduled hard-invalidate + scheduled RTM_DELADDR) was found
// to occasionally remove the downstream router's route out from under it;
// removing it in favor of "let the kernel do its job" is the fix.

struct pd_lease_watcher {
	struct relayd_event event;
	char leasefile[256];
	char leasedir[256];
	char leasebase[256];
	struct relayd_interface *target_slave;
	int addr_rtnl_socket;
	uint32_t addr_rtnl_seq;
	struct in6_addr applied_slave_addr; // last /64 host address we set on target_slave
	bool have_applied_slave_addr;

	// Last delegated prefix we actually applied (on-link address + fed to
	// update() via pd_addr_pending), tracked independently of
	// iface->pd_addr[]. iface->pd_addr[] is only committed by update()
	// once it gets around to consuming pd_addr_pending -- which can lag
	// behind a lease-file change by up to the 2s reconf tick (or happen
	// sooner, if a client packet arrives first) -- so it can't be used
	// here to tell "did the delegation itself just change" without a
	// race. These fields are ours alone and updated the instant we parse
	// a new lease, same as applied_slave_addr above.
	struct in6_addr applied_prefix_addr;
	uint8_t applied_prefix_len;
	bool have_applied_prefix;
};

static struct pd_lease_watcher watcher;

static void pd_watcher_handle_event(struct relayd_event *event);
static bool pd_watcher_parse_and_apply(void);

// Initialize the watcher: open inotify, watch the directory containing
// the lease file (watching the file itself is unreliable across the
// atomic rename-based updates some dhclient builds perform), and do an
// initial parse so we don't wait for the first change event.
int init_pd_lease_watcher(const char *leasefile, struct relayd_interface *target_slave) {
	memset(&watcher, 0, sizeof(watcher));
	watcher.target_slave = target_slave;

	if (!leasefile || !leasefile[0]) {
		syslog(LOG_ERR, "pd-lease-watcher: no lease file given");
		return -1;
	}

	size_t len = strlen(leasefile);
	if (len >= sizeof(watcher.leasefile)) {
		syslog(LOG_ERR, "pd-lease-watcher: lease file path too long");
		return -1;
	}
	memcpy(watcher.leasefile, leasefile, len + 1);

	// Split into directory + basename for the inotify watch
	const char *slash = strrchr(leasefile, '/');
	if (slash) {
		size_t dirlen = slash - leasefile;
		if (dirlen == 0) {
			dirlen = 1; // root
		}
		if (dirlen >= sizeof(watcher.leasedir)) {
			dirlen = sizeof(watcher.leasedir) - 1;
		}
		memcpy(watcher.leasedir, leasefile, dirlen);
		watcher.leasedir[dirlen] = 0;
		strncpy(watcher.leasebase, slash + 1, sizeof(watcher.leasebase) - 1);
	} else {
		strcpy(watcher.leasedir, ".");
		strncpy(watcher.leasebase, leasefile, sizeof(watcher.leasebase) - 1);
	}

	int fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
	if (fd < 0) {
		syslog(LOG_ERR, "pd-lease-watcher: inotify_init1 failed: %s", strerror(errno));
		return -1;
	}

	// Watch the directory rather than the file itself: many dhclient
	// implementations update the lease file via unlink+rename or
	// truncate+rewrite, both of which can invalidate a direct watch
	// on the file's inode.
	int wd = inotify_add_watch(fd, watcher.leasedir, IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE);
	if (wd < 0) {
		syslog(LOG_ERR, "pd-lease-watcher: inotify_add_watch(%s) failed: %s", watcher.leasedir, strerror(errno));
		close(fd);
		return -1;
	}

	watcher.event.socket = fd;
	watcher.event.handle_event = pd_watcher_handle_event;
	watcher.event.handle_dgram = NULL;

	if (relayd_register_event(&watcher.event)) {
		syslog(LOG_ERR, "pd-lease-watcher: failed to register with event loop");
		close(fd);
		return -1;
	}

	watcher.addr_rtnl_socket = -1;
	if (pd_watcher_auto_address) {
		watcher.addr_rtnl_socket = relayd_open_rtnl_socket();
		if (watcher.addr_rtnl_socket < 0)
			syslog(LOG_WARNING,
				"pd-lease-watcher: failed to open rtnl "
				"socket, on-link address on %s will not be "
				"auto-configured (RAs will likely omit the "
				"delegated prefix)",
				target_slave->ifname);
	}

	syslog(LOG_NOTICE, "pd-lease-watcher: watching %s for interface %s", watcher.leasefile, target_slave->ifname);

	// Parse once at startup so we don't have to wait for a change event
	// if the lease file already has a valid prefix (e.g. after a restart
	// of 6relayd while dhclient keeps running).
	if (!pd_watcher_parse_and_apply())
		syslog(LOG_WARNING, "pd-lease-watcher: no valid iaprefix found "
							"on startup, waiting for changes");

	return 0;
}

// inotify fd became readable
static void pd_watcher_handle_event(struct relayd_event *event) {
	uint8_t buf[PD_WATCHER_INOTIFY_BUF_SIZE] __attribute__((aligned(__alignof__(struct inotify_event))));

	bool relevant = false;

	while (true) {
		ssize_t len = read(event->socket, buf, sizeof(buf));
		if (len <= 0) {
			if (errno == EAGAIN)
				break;
			else
				continue;
		}

		for (uint8_t *p = buf; p < buf + len;) {
			struct inotify_event *ev = (struct inotify_event *)p;
			if (ev->len > 0 && !strcmp(ev->name, watcher.leasebase))
				relevant = true;
			p += sizeof(struct inotify_event) + ev->len;
		}
	}

	if (!relevant)
		return;

	syslog(LOG_INFO, "pd-lease-watcher: lease file changed, re-parsing");
	pd_watcher_parse_and_apply();
}

// Parse "starts N;" / "preferred-life N;" / "max-life N;" that follow an
// iaprefix line, giving us valid/preferred lifetimes. Falls back to
// conservative defaults if parsing fails, rather than propagating 0
// (which would immediately deprecate/invalidate the prefix downstream).
static void parse_lifetimes(const char *block, uint32_t *preferred, uint32_t *valid) {
	*preferred = 1800; // conservative fallback
	*valid = 3600;

	const char *p = strstr(block, "preferred-life");
	if (p)
		*preferred = (uint32_t)strtoul(p + strlen("preferred-life"), NULL, 10);

	const char *v = strstr(block, "max-life");
	if (v)
		*valid = (uint32_t)strtoul(v + strlen("max-life"), NULL, 10);
}

// Fill in the low 64 bits of 'addr' with the modified EUI-64 derived from
// iface's own MAC address (RFC 4291 appendix A): split the 48-bit MAC
// around the middle, insert ff:fe, and flip the universal/local bit. Used
// so the address we put on br0 is a normal, stable interface identifier
// instead of a fixed ::1 -- among other things this means the address
// changes together with the prefix (a real, different IPv6 address) rather
// than being the "same" address rebound to a new prefix, which matters for
// how we retire the previous one (see the retirement-policy comment near
// the top of this file).
static void pd_watcher_eui64_addr(struct in6_addr *addr, const uint8_t mac[6]) {
	addr->s6_addr[8] = mac[0] ^ 0x02;
	addr->s6_addr[9] = mac[1];
	addr->s6_addr[10] = mac[2];
	addr->s6_addr[11] = 0xff;
	addr->s6_addr[12] = 0xfe;
	addr->s6_addr[13] = mac[3];
	addr->s6_addr[14] = mac[4];
	addr->s6_addr[15] = mac[5];
}

// Install (or refresh) a /64 on-link address on the target slave interface,
// derived from the first /64 of the delegated prefix plus the interface's
// own EUI-64 host part.
//
// Why this is needed: router.c's send_router_advert() builds the RA's
// Prefix Information Options by calling relayd_get_interface_addresses(),
// which does a plain RTM_GETADDR netlink dump of addresses the *kernel*
// already has configured on the interface. That path is entirely
// independent of iface->pd_addr[] -- so a prefix injected only via
// pd_watcher_parse_and_apply() above is invisible to it. Without a real
// kernel address inside the delegated range, br0's RAs never carry a PIO
// for the delegated prefix, and a downstream PD requester can be left
// waiting even though our DHCPv6-PD REPLY already carries the right
// prefix. NLM_F_REPLACE makes this idempotent, so it's safe to call on
// every parse (also keeps the kernel's preferred/valid lifetimes fresh).
// If applied_addr is non-NULL, the actual address applied (prefix + our
// EUI-64, or the ::1 fallback) is written there for the caller to remember.
static void pd_watcher_set_slave_address(
	struct relayd_interface *iface, const struct in6_addr *prefix, uint32_t preferred, uint32_t valid, struct in6_addr *applied_addr) {
	struct in6_addr addr = *prefix;
	addr.s6_addr32[2] = 0;
	addr.s6_addr32[3] = 0;

	uint8_t mac[6];
	if (relayd_get_interface_mac(iface->ifname, mac) < 0) {
		syslog(LOG_WARNING,
			"pd-lease-watcher: failed to read MAC of %s, "
			"falling back to ::1 host address",
			iface->ifname);
		addr.s6_addr32[3] = htonl(1);
	} else {
		pd_watcher_eui64_addr(&addr, mac);
	}

	if (applied_addr)
		*applied_addr = addr;

	if (watcher.addr_rtnl_socket < 0)
		return;

	struct req {
		struct nlmsghdr nh;
		struct ifaddrmsg ifa;
		struct rtattr rta_local;
		struct in6_addr local;
		struct rtattr rta_cache;
		struct ifa_cacheinfo cache;
	} req = {
		{sizeof(req), RTM_NEWADDR, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE, ++watcher.addr_rtnl_seq, 0},
		{AF_INET6, 64, 0, RT_SCOPE_UNIVERSE, iface->ifindex},
		{sizeof(struct rtattr) + sizeof(struct in6_addr), IFA_LOCAL},
		addr,
		{sizeof(struct rtattr) + sizeof(struct ifa_cacheinfo), IFA_CACHEINFO},
		{preferred, valid, 0, 0},
	};

	char addrbuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &addr, addrbuf, sizeof(addrbuf));

	if (send(watcher.addr_rtnl_socket, &req, sizeof(req), MSG_DONTWAIT) < 0)
		syslog(LOG_WARNING,
			"pd-lease-watcher: failed to set address "
			"%s/64 on %s: %s",
			addrbuf, iface->ifname, strerror(errno));
	else
		syslog(LOG_INFO,
			"pd-lease-watcher: set on-link address %s/64 "
			"on %s (preferred=%u valid=%u)",
			addrbuf, iface->ifname, preferred, valid);
}

// Remove a previously-applied on-link address from the target slave. Only
// called on clean 6relayd shutdown (deinit_pd_lease_watcher() via
// pd_watcher_invalidate_current(..., immediate=true)) -- there's no process
// left running afterwards to let the address expire on its own kernel
// lifetime, so we explicitly take it down instead. Not used for ordinary
// prefix changes/rotations; see the retirement-policy comment near the top
// of this file for why.
static void pd_watcher_del_slave_address(struct relayd_interface *iface, const struct in6_addr *addr) {
	if (watcher.addr_rtnl_socket < 0)
		return;

	struct req {
		struct nlmsghdr nh;
		struct ifaddrmsg ifa;
		struct rtattr rta_local;
		struct in6_addr local;
	} req = {
		{sizeof(req), RTM_DELADDR, NLM_F_REQUEST, ++watcher.addr_rtnl_seq, 0},
		{AF_INET6, 64, 0, RT_SCOPE_UNIVERSE, iface->ifindex},
		{sizeof(struct rtattr) + sizeof(struct in6_addr), IFA_LOCAL},
		*addr,
	};

	char addrbuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, addr, addrbuf, sizeof(addrbuf));

	if (send(watcher.addr_rtnl_socket, &req, sizeof(req), MSG_DONTWAIT) < 0)
		syslog(LOG_WARNING,
			"pd-lease-watcher: failed to remove stale address "
			"%s/64 on %s: %s",
			addrbuf, iface->ifname, strerror(errno));
	else
		syslog(LOG_NOTICE,
			"pd-lease-watcher: removed stale on-link address "
			"%s/64 on %s (prefix delegation changed)",
			addrbuf, iface->ifname);
}

// Shared teardown used both on clean shutdown (see deinit_pd_lease_watcher()
// below) and whenever pd_watcher_parse_and_apply() finds the delegation
// currently unusable (lease file missing / empty / lacking an iaprefix --
// typically a ppp0 reconnect in progress).
//
// immediate=true (shutdown only): explicitly remove the on-link address
// from br0 right now, since nothing will be around afterwards to let it
// expire naturally.
//
// immediate=false (lease file trouble, e.g. a ppp0 reconnect in progress):
// we deliberately do *nothing* to the on-link address or send any RA here.
// Downstream is DHCPv6-PD/NA only (SLAAC is off on the requesting router),
// so there's nothing that needs an early invalidation notice; the address
// already on br0 simply keeps its existing kernel lifetime and expires (and
// gets removed) on its own if the delegation never comes back before then.
// If the same or a new prefix shows up again first, pd_watcher_parse_and_apply()
// just re-applies/replaces it as usual.
//
// Either way, pd_addr_pending is flipped to an empty, valid update right
// away so update() (dhcpv6-ia.c) stops handing this delegation to *new*
// DHCPv6-PD requests immediately.
static void pd_watcher_invalidate_current(const char *reason, bool immediate) {
	if (!watcher.have_applied_prefix)
		return; // nothing currently applied -- nothing to tear down

	struct relayd_interface *iface = watcher.target_slave;

	syslog(LOG_NOTICE, "pd-lease-watcher: %s, %s previously-applied prefix", reason,
		immediate ? "invalidating" : "leaving on-link address of (letting it expire naturally on)");

	if (immediate) {
		if (pd_watcher_auto_address && watcher.have_applied_slave_addr)
			pd_watcher_del_slave_address(iface, &watcher.applied_slave_addr);
	}

	watcher.have_applied_prefix = false;
	watcher.have_applied_slave_addr = false;

	iface->pd_addr_pending_len = 0;
	iface->pd_addr_pending_valid = true; // one-shot: tells update() there's new (empty) data
	iface->pd_watcher_managed = true;
	iface->pd_reconf = true; // wake reconf_timer promptly instead of waiting up to 2s
}

// Read the lease file, find the (last, i.e. most recent) "iaprefix" entry,
// and if found and different from what we currently have, apply it to
// target_slave->pd_addr[0].
static bool pd_watcher_parse_and_apply(void) {
	FILE *fp = fopen(watcher.leasefile, "r");
	if (!fp) {
		syslog(LOG_WARNING, "pd-lease-watcher: cannot open %s: %s", watcher.leasefile, strerror(errno));
		pd_watcher_invalidate_current("lease file missing", false);
		return false;
	}

	char *contents = NULL;
	size_t cap = 0, total = 0;
	char chunk[4096];
	size_t n;
	while ((n = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
		if (total + n + 1 > cap) {
			cap = (total + n + 1) * 2;
			char *tmp = realloc(contents, cap);
			if (!tmp) {
				free(contents);
				fclose(fp);
				return false;
			}
			contents = tmp;
		}
		memcpy(contents + total, chunk, n);
		total += n;
	}
	fclose(fp);

	if (!contents) {
		pd_watcher_invalidate_current("lease file empty/unreadable", false);
		return false;
	}
	contents[total] = 0;

	// Find the LAST "iaprefix" occurrence: dhclient lease files are
	// append-only logs of every lease ever seen, so the most recent
	// (and currently valid) entry is always the last one in the file.
	char *last = NULL;
	for (char *p = strstr(contents, "iaprefix"); p; p = strstr(p + 1, "iaprefix"))
		last = p;

	if (!last) {
		syslog(LOG_WARNING, "pd-lease-watcher: no iaprefix found in %s", watcher.leasefile);
		pd_watcher_invalidate_current("no iaprefix in lease file (PD likely down)", false);
		free(contents);
		return false;
	}

	char addrbuf[INET6_ADDRSTRLEN] = {0};
	unsigned int prefixlen = 0;

	// Expected: iaprefix <addr>/<len> {
	if (sscanf(last, "iaprefix %45[0-9a-fA-F:]/%u", addrbuf, &prefixlen) != 2) {
		syslog(LOG_WARNING, "pd-lease-watcher: failed to parse iaprefix line: %.80s", last);
		pd_watcher_invalidate_current("iaprefix line unparseable (partial write?)", false);
		free(contents);
		return false;
	}

	struct in6_addr addr;
	if (inet_pton(AF_INET6, addrbuf, &addr) != 1) {
		syslog(LOG_WARNING, "pd-lease-watcher: invalid address in iaprefix: %s", addrbuf);
		pd_watcher_invalidate_current("iaprefix address unparseable (partial write?)", false);
		free(contents);
		return false;
	}

	// Grab the block right after the match (up to the next closing
	// brace) so parse_lifetimes() doesn't wander into unrelated content.
	char block[512] = {0};
	const char *end = strchr(last, '}');
	size_t blocklen = end ? (size_t)(end - last) : strlen(last);
	if (blocklen >= sizeof(block))
		blocklen = sizeof(block) - 1;
	memcpy(block, last, blocklen);

	uint32_t preferred, valid;
	parse_lifetimes(block, &preferred, &valid);

	struct relayd_interface *iface = watcher.target_slave;

	// Snapshot the previous prefix *before* we overwrite our bookkeeping
	// below. Kept mainly for logging/bookkeeping purposes now -- we no
	// longer act on the old prefix when it changes (see the comment
	// below, near pd_watcher_set_slave_address()); it's simply left in
	// place to expire on its own kernel lifetime.
	//
	// This is tracked here (watcher.applied_prefix_*) rather than read
	// back from iface->pd_addr[]: the latter is only committed by
	// update() once it gets around to consuming pd_addr_pending[] below,
	// which can lag behind by up to the 2s reconf tick. Using it here
	// would race against that and could compare against a stale-stale
	// (i.e. two generations old) prefix instead of the one we actually
	// applied last.
	bool had_old_prefix = watcher.have_applied_prefix;
	struct in6_addr old_addr = watcher.applied_prefix_addr;
	uint8_t old_prefixlen = watcher.applied_prefix_len;

	bool changed = !had_old_prefix || memcmp(&old_addr, &addr, sizeof(addr)) || old_prefixlen != prefixlen;

	long now = pd_watcher_monotonic_time();

	// Hand the new prefix to update() (dhcpv6-ia.c) via the pending
	// staging area rather than writing iface->pd_addr[] directly: update()
	// needs pd_addr[] to still hold the *previous* commit when it diffs
	// against this, so it can tell a real prefix change happened and
	// reconfigure downstream DHCPv6-PD/NA clients accordingly. Writing
	// here directly would make update()'s "fresh" and "previous" values
	// the same array, and it would never see a difference.
	iface->pd_addr_pending[0].addr = addr;
	iface->pd_addr_pending[0].prefix = prefixlen;
	// Lifetimes from the lease file are relative (seconds from "now").
	// Store them as absolute monotonic-clock deadlines right away, since
	// that's the format dhcpv6-ia.c's update() expects to find here (it
	// un-absolutizes by subtracting the current time, then
	// re-absolutizes). Storing a raw relative value here instead would
	// make the very first update() after this call treat e.g. "172800"
	// as if it were already a deadline in the past, zeroing the prefix's
	// lifetime immediately.
	iface->pd_addr_pending[0].preferred = (uint32_t)preferred + (uint32_t)now;
	iface->pd_addr_pending[0].valid = (uint32_t)valid + (uint32_t)now;
	iface->pd_addr_pending_len = 1;
	iface->pd_addr_pending_valid = true; // one-shot: tells update() there's new data to diff
	iface->pd_watcher_managed = true;	 // persistent: never read this iface via netlink
	iface->pd_reconf = true;			 // one-shot: hint reconf_timer to run update() promptly

	iface->pd_addr_applied_at = now; // informational only now; update() no
	// longer relies on this for its math

	watcher.applied_prefix_addr = addr;
	watcher.applied_prefix_len = prefixlen;
	watcher.have_applied_prefix = true;

	if (changed) {
		syslog(LOG_NOTICE,
			"pd-lease-watcher: applied prefix %s/%u to %s "
			"(preferred=%u valid=%u)",
			addrbuf, prefixlen, iface->ifname, preferred, valid);

		// Without a kick here, the *next* RA carrying a real (nonzero)
		// router_lifetime only goes out at the next periodic timer_rs
		// tick, which is random between MinRtrAdvInterval and
		// MaxRtrAdvInterval (200-600s) -- so a downstream router (e.g. a
		// MikroTik CE) can end up holding a perfectly valid new prefix,
		// handing out addresses on its own LAN, with zero default route
		// out for up to ten minutes. Forcing timer_rs to fire in ~1s makes
		// send_router_advert() re-check addresses immediately, see the
		// on-link address we're about to (re)apply below, and restore
		// router_lifetime right away.
		if (iface->timer_rs.socket > 0) {
			struct itimerspec its = {{0, 0}, {1, 0}};
			timerfd_settime(iface->timer_rs.socket, 0, &its, NULL);
		}
	}

	if (pd_watcher_auto_address) {
		// If the prefix changed (had_old_prefix/old_addr/old_prefixlen,
		// computed above for the 'changed' check), we deliberately do
		// nothing to the old address here: it's a genuinely different
		// IPv6 address (host part is our EUI-64, network part is the old
		// /64), so simply applying the new one below leaves the old one
		// in place on br0 with whatever kernel lifetime it already had,
		// and the kernel expires/removes it on its own once that runs
		// out. No RA invalidation, no RTM_DELADDR -- see the
		// retirement-policy comment near the top of this file for why.
		struct in6_addr new_host_addr;
		pd_watcher_set_slave_address(iface, &addr, preferred, valid, &new_host_addr);

		watcher.applied_slave_addr = new_host_addr;
		watcher.have_applied_slave_addr = true;
	}

	free(contents);
	return true;
}

// Shutdown counterpart to the "changed" branch above: on a clean exit
// (SIGTERM/SIGHUP/SIGINT -> main()'s do_stop path) we don't get a new,
// different prefix to replace the old one with -- we just need to undo
// what we applied, exactly as if the delegation had gone away. Without
// this, br0 would be left holding a kernel address with its original,
// often multi-day valid lifetime, and downstream hosts would keep the
// prefix in their RA-derived config until that lifetime naturally expired,
// even though nothing is refreshing (or, after a restart with a genuinely
// new prefix, correcting) it anymore.
void deinit_pd_lease_watcher(void) {
	if (!watcher.target_slave)
		return; // init_pd_lease_watcher() was never called (-w not given)

	pd_watcher_invalidate_current("6relayd shutting down", true);
}
