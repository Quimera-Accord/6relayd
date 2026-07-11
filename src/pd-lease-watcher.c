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

struct pd_lease_watcher {
	struct relayd_event event;
	char leasefile[256];
	char leasedir[256];
	char leasebase[256];
	struct relayd_interface *target_slave;
	int addr_rtnl_socket;
	uint32_t addr_rtnl_seq;
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

// Install (or refresh) a /64 on-link address (host part ::1) on the
// target slave interface, derived from the first /64 of the delegated
// prefix.
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
static void pd_watcher_set_slave_address(struct relayd_interface *iface, const struct in6_addr *prefix, uint32_t preferred, uint32_t valid) {
	if (watcher.addr_rtnl_socket < 0)
		return;

	struct in6_addr addr = *prefix;
	addr.s6_addr32[2] = 0;
	addr.s6_addr32[3] = htonl(1); // host part ::1, subnet id 0 within /64

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

// Read the lease file, find the (last, i.e. most recent) "iaprefix" entry,
// and if found and different from what we currently have, apply it to
// target_slave->pd_addr[0].
static bool pd_watcher_parse_and_apply(void) {
	FILE *fp = fopen(watcher.leasefile, "r");
	if (!fp) {
		syslog(LOG_WARNING, "pd-lease-watcher: cannot open %s: %s", watcher.leasefile, strerror(errno));
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
		free(contents);
		return false;
	}

	char addrbuf[INET6_ADDRSTRLEN] = {0};
	unsigned int prefixlen = 0;

	// Expected: iaprefix <addr>/<len> {
	if (sscanf(last, "iaprefix %45[0-9a-fA-F:]/%u", addrbuf, &prefixlen) != 2) {
		syslog(LOG_WARNING, "pd-lease-watcher: failed to parse iaprefix line: %.80s", last);
		free(contents);
		return false;
	}

	struct in6_addr addr;
	if (inet_pton(AF_INET6, addrbuf, &addr) != 1) {
		syslog(LOG_WARNING, "pd-lease-watcher: invalid address in iaprefix: %s", addrbuf);
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

	bool changed = (iface->pd_addr_len != 1) || memcmp(&iface->pd_addr[0].addr, &addr, sizeof(addr)) || iface->pd_addr[0].prefix != prefixlen;

	iface->pd_addr[0].addr = addr;
	iface->pd_addr[0].prefix = prefixlen;
	iface->pd_addr[0].preferred = preferred;
	iface->pd_addr[0].valid = valid;
	iface->pd_addr_len = 1;
	iface->pd_watcher_managed = true; // persistent: never read this iface via netlink
	iface->pd_reconf = true;		  // one-shot: hint reconf_timer to run update() promptly

	// Lifetimes above are relative (straight from the lease file's
	// preferred-life/max-life, in seconds from "now"). Stamp "now" so
	// dhcpv6-ia.c's update() knows the reference point to compute
	// elapsed time from on its next run, instead of treating these as
	// already-absolute netlink-style values.
	iface->pd_addr_applied_at = pd_watcher_monotonic_time();

	if (changed) {
		syslog(LOG_NOTICE,
			"pd-lease-watcher: applied prefix %s/%u to %s "
			"(preferred=%u valid=%u)",
			addrbuf, prefixlen, iface->ifname, preferred, valid);
	}

	if (pd_watcher_auto_address)
		pd_watcher_set_slave_address(iface, &addr, preferred, valid);

	free(contents);
	return true;
}
