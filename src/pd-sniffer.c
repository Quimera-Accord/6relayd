/**
 * pd-sniffer.c
 *
 * Sniffs DHCPv6 traffic on the WAN (master) interface -- e.g. ppp0, where
 * our own dhclient is requesting a delegated prefix from the ISP -- for
 * REPLY packets carrying an IA_PD, and applies the delegated prefix(es)
 * directly to a target slave interface (e.g. br0), the same way the old
 * lease-file watcher (pd-lease-watcher.c) did.
 *
 * Why sniff the wire instead of watching dhclient's lease file: the lease
 * file is dhclient's own persistence mechanism, written on its own
 * schedule (and via unlink+rename/truncate+rewrite, which is why the old
 * watcher had to watch the containing directory rather than the file
 * itself) -- so there's an unavoidable, somewhat unpredictable lag between
 * "dhclient got a new prefix" and "the lease file reflects it". Reading
 * the REPLY packet itself off the wire has none of that: we react in the
 * same event-loop tick the packet arrives in, and we're not depending on
 * dhclient's file format staying stable either (we don't care what dhclient
 * client is even in use, as long as *something* is doing DHCPv6-PD on
 * wan_iface and the ISP's REPLY is visible there, which it always is --
 * it's addressed to the DHCPv6 client port on this host).
 *
 * We use an AF_PACKET/SOCK_DGRAM ("cooked") socket rather than SOCK_RAW:
 * SOCK_DGRAM strips whatever link-layer header the interface has (or, for
 * ppp0, often doesn't reliably have one to begin with -- see the kernel's
 * own reasoning for inventing the "Linux cooked capture" pseudo-header for
 * exactly this case) before handing us the frame, so what we get starts
 * directly at the IPv6 header regardless of whether wan_iface is Ethernet,
 * PPP, or anything else. Same technique ndp.c already uses for its NDP
 * intercept socket on the LAN side.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <sys/timerfd.h>

#include "6relayd.h"
#include "dhcpv6.h"
#include "pd-sniffer.h"

bool pd_sniffer_dry_run = false;

struct pd_sniffer {
	struct relayd_event event;
	struct relayd_interface *wan_iface;
	struct relayd_interface *target_slave;
	int addr_rtnl_socket;
	uint32_t addr_rtnl_seq;
	struct in6_addr applied_slave_addr; // last /64 host address we set on target_slave
	bool have_applied_slave_addr;

	char fallback_leasefile[256];
	bool have_captured_any;
};

static struct pd_sniffer sniffer;

static void pd_sniffer_handle_packet(void *addr, void *data, size_t len, struct relayd_interface *iface);

// Only match on IPv6 + UDP here; port 546 (DHCPv6 client) and message type
// (REPLY) are checked in userspace once we can also see the UDP payload,
// rather than trying to encode all of that (and cope with any IPv6
// extension headers that might sit between the IPv6 header and UDP, which
// a fixed-offset BPF program like this can't skip) as jump math here.
static struct sock_filter bpf[] = {
	BPF_STMT(BPF_LD | BPF_B | BPF_ABS, offsetof(struct ip6_hdr, ip6_nxt)),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 1),
	BPF_STMT(BPF_RET | BPF_K, 0xffffffff),
	BPF_STMT(BPF_RET | BPF_K, 0),
};
static const struct sock_fprog bpf_prog = {sizeof(bpf) / sizeof(*bpf), bpf};

// Fill in the low 64 bits of 'addr' with the modified EUI-64 derived from
// iface's own MAC address (RFC 4291 appendix A): split the 48-bit MAC
// around the middle, insert ff:fe, and flip the universal/local bit. Used
// so the address we put on br0 is a normal, stable interface identifier
// instead of a fixed ::1.
static void pd_sniffer_eui64_addr(struct in6_addr *addr, const uint8_t mac[6]) {
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
// own EUI-64 host part. See pd_watcher_set_slave_address() in the old
// pd-lease-watcher.c for the original, more detailed rationale -- same
// idea here: router.c's send_router_advert() only sees prefixes that are
// actually present as kernel addresses on the interface (via
// relayd_get_interface_addresses()), so without this the delegated prefix
// would never show up in RAs even though we already told the ISP's server
// (implicitly, by being the one whose dhclient requested it) we're using
// it. NLM_F_REPLACE makes this idempotent, so it's safe to call on every
// REPLY (also keeps the kernel's preferred/valid lifetimes fresh).
// If applied_addr is non-NULL, the actual address applied (prefix + our
// EUI-64, or the ::1 fallback) is written there for the caller to remember.
static void pd_sniffer_set_slave_address(
	struct relayd_interface *iface, const struct in6_addr *prefix, uint32_t preferred, uint32_t valid, struct in6_addr *applied_addr) {
	struct in6_addr addr = *prefix;
	addr.s6_addr32[2] = 0;
	addr.s6_addr32[3] = 0;

	uint8_t mac[6];
	if (relayd_get_interface_mac(iface->ifname, mac) < 0) {
		syslog(LOG_WARNING,
			"pd-sniffer: failed to read MAC of %s, "
			"falling back to ::1 host address",
			iface->ifname);
		addr.s6_addr32[3] = htonl(1);
	} else {
		pd_sniffer_eui64_addr(&addr, mac);
	}

	if (applied_addr)
		*applied_addr = addr;

	char addrbuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &addr, addrbuf, sizeof(addrbuf));

	if (pd_sniffer_dry_run) {
		syslog(LOG_NOTICE,
			"pd-sniffer: [DRY-RUN] would set on-link address "
			"%s/64 on %s (preferred=%u valid=%u)",
			addrbuf, iface->ifname, preferred, valid);
		return;
	}

	if (sniffer.addr_rtnl_socket < 0)
		return;

	struct req {
		struct nlmsghdr nh;
		struct ifaddrmsg ifa;
		struct rtattr rta_local;
		struct in6_addr local;
		struct rtattr rta_cache;
		struct ifa_cacheinfo cache;
	} req = {
		{sizeof(req), RTM_NEWADDR, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE, ++sniffer.addr_rtnl_seq, 0},
		{AF_INET6, 64, 0, RT_SCOPE_UNIVERSE, iface->ifindex},
		{sizeof(struct rtattr) + sizeof(struct in6_addr), IFA_LOCAL},
		addr,
		{sizeof(struct rtattr) + sizeof(struct ifa_cacheinfo), IFA_CACHEINFO},
		{preferred, valid, 0, 0},
	};

	if (send(sniffer.addr_rtnl_socket, &req, sizeof(req), MSG_DONTWAIT) < 0)
		syslog(LOG_WARNING,
			"pd-sniffer: failed to set address "
			"%s/64 on %s: %s",
			addrbuf, iface->ifname, strerror(errno));
	else
		syslog(LOG_INFO,
			"pd-sniffer: set on-link address %s/64 "
			"on %s (preferred=%u valid=%u)",
			addrbuf, iface->ifname, preferred, valid);
}

// Remove a previously-applied on-link address from the target slave. Only
// called on clean 6relayd shutdown (deinit_pd_sniffer()) -- ordinary
// prefix changes/rotations deliberately leave the old address alone to
// expire on its own kernel lifetime; see the comment in
// pd_sniffer_apply_prefix() for why.
static void pd_sniffer_del_slave_address(struct relayd_interface *iface, const struct in6_addr *addr) {
	char addrbuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, addr, addrbuf, sizeof(addrbuf));

	if (pd_sniffer_dry_run) {
		syslog(LOG_NOTICE,
			"pd-sniffer: [DRY-RUN] would remove on-link address "
			"%s/64 on %s",
			addrbuf, iface->ifname);
		return;
	}

	if (sniffer.addr_rtnl_socket < 0)
		return;

	struct req {
		struct nlmsghdr nh;
		struct ifaddrmsg ifa;
		struct rtattr rta_local;
		struct in6_addr local;
	} req = {
		{sizeof(req), RTM_DELADDR, NLM_F_REQUEST, ++sniffer.addr_rtnl_seq, 0},
		{AF_INET6, 64, 0, RT_SCOPE_UNIVERSE, iface->ifindex},
		{sizeof(struct rtattr) + sizeof(struct in6_addr), IFA_LOCAL},
		*addr,
	};

	if (send(sniffer.addr_rtnl_socket, &req, sizeof(req), MSG_DONTWAIT) < 0)
		syslog(LOG_WARNING,
			"pd-sniffer: failed to remove stale address "
			"%s/64 on %s: %s",
			addrbuf, iface->ifname, strerror(errno));
	else
		syslog(LOG_NOTICE,
			"pd-sniffer: removed on-link address "
			"%s/64 on %s",
			addrbuf, iface->ifname);
}

// Apply one delegated prefix (from a parsed IA_PREFIX option) to
// target_slave, exactly the way pd-lease-watcher.c's
// pd_watcher_parse_and_apply() used to: hand it to update() (dhcpv6-ia.c)
// via the pending staging area, kick timer_rs so the next RA reflects it
// promptly, and (if enabled) install/refresh the EUI-64 on-link address.
//
// index selects which slot of iface->pd_addr_pending[] this prefix goes
// into -- see init_pd_sniffer()'s header comment on why the REPLY can, in
// principle, carry more than one IA_PD/IA_PREFIX even though in practice
// (as of this writing) our ISP has only ever handed out one.
static void pd_sniffer_apply_prefix(size_t index, const struct in6_addr *addr, uint8_t prefixlen, uint32_t preferred, uint32_t valid) {
	struct relayd_interface *iface = sniffer.target_slave;

	if (index >= ARRAY_SIZE(iface->pd_addr_pending))
		return; // more IA_PREFIXes than we have room for; drop the rest

	char addrbuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, addr, addrbuf, sizeof(addrbuf));

	if (pd_sniffer_dry_run) {
		// Deliberately don't touch iface->pd_addr_pending[]/pd_reconf/
		// timer_rs here: those feed dhcpv6-ia.c's update() and the RA
		// sender for real, which would make this not a dry run. Still
		// walk through pd_sniffer_set_slave_address() below (its own
		// dry-run branch logs what it would've done and returns before
		// touching netlink), so a dry run reports the exact same
		// decisions -- prefix parsed, address that would be
		// configured -- without applying any of them.
		syslog(LOG_NOTICE,
			"pd-sniffer: [DRY-RUN] would apply prefix %s/%u to %s "
			"(preferred=%u valid=%u)",
			addrbuf, prefixlen, iface->ifname, preferred, valid);

		if (index == 0)
			pd_sniffer_set_slave_address(iface, addr, preferred, valid, NULL);

		return;
	}

	// Lifetimes off the wire are relative (seconds from "now"), same as
	// they were when read from the lease file. Store them as absolute
	// monotonic-clock deadlines right away, since that's the format
	// dhcpv6-ia.c's update() expects to find here (see the old
	// pd-lease-watcher.c for the detailed reasoning -- unchanged here).
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	long now = ts.tv_sec;

	iface->pd_addr_pending[index].addr = *addr;
	iface->pd_addr_pending[index].prefix = prefixlen;
	iface->pd_addr_pending[index].preferred = (uint32_t)preferred + (uint32_t)now;
	iface->pd_addr_pending[index].valid = (uint32_t)valid + (uint32_t)now;

	syslog(LOG_NOTICE,
		"pd-sniffer: applied prefix %s/%u to %s "
		"(preferred=%u valid=%u)",
		addrbuf, prefixlen, iface->ifname, preferred, valid);

	// Without a kick here, the *next* RA carrying a real (nonzero)
	// router_lifetime only goes out at the next periodic timer_rs tick,
	// which is random between MinRtrAdvInterval and MaxRtrAdvInterval
	// (200-600s) -- so a downstream router (e.g. a MikroTik CE) can end
	// up holding a perfectly valid new prefix, handing out addresses on
	// its own LAN, with zero default route out for up to ten minutes.
	// Forcing timer_rs to fire in ~1s makes send_router_advert()
	// re-check addresses immediately, see the on-link address we're
	// about to (re)apply below, and restore router_lifetime right away.
	if (iface->timer_rs.socket > 0) {
		struct itimerspec its = {{0, 0}, {1, 0}};
		timerfd_settime(iface->timer_rs.socket, 0, &its, NULL);
	}

	if (index == 0) {
		// Only the first prefix gets an on-link address: that's the one
		// router.c actually needs to see via relayd_get_interface_addresses()
		// to build RA PIOs (see pd_sniffer_set_slave_address()'s comment).
		// A second/third simultaneous IA_PD (currently never seen from our
		// ISP -- see the header comment) would still be forwarded to
		// downstream DHCPv6-PD/NA clients via pd_addr_pending[], just
		// without its own on-link address on br0.
		//
		// As with the old lease-file watcher: if the prefix changed, we
		// deliberately do nothing to whatever address was there before.
		// It's a genuinely different IPv6 address (host part is our
		// EUI-64, network part is the old /64), so simply applying the
		// new one leaves the old one in place with whatever kernel
		// lifetime it already had, and the kernel expires/removes it on
		// its own once that runs out. No RTM_DELADDR here.
		struct in6_addr new_host_addr;
		pd_sniffer_set_slave_address(iface, addr, preferred, valid, &new_host_addr);

		sniffer.applied_slave_addr = new_host_addr;
		sniffer.have_applied_slave_addr = true;
	}
}

// Parse a DHCPv6 REPLY payload (starting at the message header, i.e. right
// after the UDP header) for IA_PD options, and apply every IA_PREFIX found
// inside them. Mirrors the nested-option walk dhcpv6-ia.c's
// handle_client_request() already does server-side for the exact same
// option layout (see its DHCPV6_OPT_IA_PD / DHCPV6_OPT_IA_PREFIX handling)
// -- reusing the same dhcpv6.h structs/macro rather than writing a new
// parser.
static void pd_sniffer_parse_reply(uint8_t *start, uint8_t *end) {
	uint16_t otype, olen;
	uint8_t *odata;

	size_t applied = 0;
	bool changed = false;

	dhcpv6_for_each_option(start, end, otype, olen, odata) {
		if (otype != DHCPV6_OPT_IA_PD || olen < sizeof(struct dhcpv6_ia_hdr) - 4)
			continue;

		struct dhcpv6_ia_hdr *ia = (struct dhcpv6_ia_hdr *)&odata[-4];

		uint8_t *sdata;
		uint16_t stype, slen;
		dhcpv6_for_each_option((uint8_t *)&ia[1], odata + olen, stype, slen, sdata) {
			if (stype != DHCPV6_OPT_IA_PREFIX || slen < sizeof(struct dhcpv6_ia_prefix) - 4)
				continue;

			struct dhcpv6_ia_prefix *p = (struct dhcpv6_ia_prefix *)&sdata[-4];
			if (!p->prefix || p->prefix > 64)
				continue; // not a usable /0-/64 delegation (see router.c's own /64 assumption elsewhere)

			struct in6_addr prefix_addr = p->addr; // copy out of the packed struct before taking its address
			pd_sniffer_apply_prefix(applied, &prefix_addr, p->prefix, ntohl(p->preferred), ntohl(p->valid));
			++applied;
			changed = true;
		}
	}

	if (!changed)
		return;

	// A REPLY was actually captured and parsed -- the sniffer works, so
	// the startup fallback (if armed) is no longer needed. This applies
	// even in dry-run: successfully parsing a REPLY is what the fallback
	// exists to guard against *not* happening, so it should stand down
	// either way rather than only when side effects were also applied.
	sniffer.have_captured_any = true;

	if (pd_sniffer_dry_run)
		return;

	struct relayd_interface *iface = sniffer.target_slave;
	iface->pd_addr_pending_len = applied;
	iface->pd_addr_pending_valid = true; // one-shot: tells update() there's new data to diff
	iface->pd_watcher_managed = true;	 // persistent: never read this iface via netlink
	iface->pd_reconf = true;			 // one-shot: hint reconf_timer to run update() promptly
}

// AF_PACKET/SOCK_DGRAM socket became readable. 'data' starts at the IPv6
// header (link-layer header already stripped by the kernel -- see the
// file-level comment on why SOCK_DGRAM rather than SOCK_RAW).
static void pd_sniffer_handle_packet(_unused void *addr, void *data, size_t len, _unused struct relayd_interface *iface) {
	if (len < sizeof(struct ip6_hdr))
		return;

	struct ip6_hdr *ip6 = data;
	if (ip6->ip6_nxt != IPPROTO_UDP)
		return; // BPF already filters this, but double-check after the cast

	uint8_t *end = (uint8_t *)data + len;
	uint8_t *udp_start = (uint8_t *)&ip6[1];
	if (udp_start + sizeof(struct udphdr) > end)
		return;

	struct udphdr *udp = (struct udphdr *)udp_start;
	if (ntohs(udp->dest) != DHCPV6_CLIENT_PORT)
		return; // not a REPLY headed for the DHCPv6 client port on this host

	uint8_t *dhcp_start = udp_start + sizeof(struct udphdr);
	if (dhcp_start + sizeof(struct dhcpv6_client_header) > end)
		return;

	struct dhcpv6_client_header *hdr = (struct dhcpv6_client_header *)dhcp_start;
	if (hdr->msg_type != DHCPV6_MSG_REPLY)
		return; // ignore Solicit/Request/Renew/Rebind etc. also seen on :546

	pd_sniffer_parse_reply(dhcp_start + sizeof(*hdr), end);
}

// Parse "preferred-life N;" / "max-life N;" that follow an iaprefix line
// in an ISC dhclient lease file, giving us relative preferred/valid
// lifetimes. Falls back to conservative defaults if parsing fails, rather
// than propagating 0 (which would immediately deprecate/invalidate the
// prefix downstream). Ported as-is from the old pd-lease-watcher.c.
static void pd_sniffer_fallback_parse_lifetimes(const char *block, uint32_t *preferred, uint32_t *valid) {
	*preferred = 1800; // conservative fallback
	*valid = 3600;

	const char *p = strstr(block, "preferred-life");
	if (p)
		*preferred = (uint32_t)strtoul(p + strlen("preferred-life"), NULL, 10);

	const char *v = strstr(block, "max-life");
	if (v)
		*valid = (uint32_t)strtoul(v + strlen("max-life"), NULL, 10);
}

// Startup-only safety net: called once, synchronously, from
// init_pd_sniffer() (no more waiting on a timer first -- the file's
// on-disk content isn't going to change just because we sat around).
// Reads fallback_leasefile, finds the most recent "iaprefix" entry (ISC
// dhclient lease files are append-only logs of every lease ever seen, so
// the last occurrence is the current one), and applies it exactly the way
// a captured REPLY would be. Ported from the old pd-lease-watcher.c's
// pd_watcher_parse_and_apply() -- same format, same parsing approach --
// minus the continuous inotify watch: this is a single read, not a new
// permanent mode of operation (see the header comment on
// init_pd_sniffer() in pd-sniffer.h).
static void pd_sniffer_fallback_read(void) {
	FILE *fp = fopen(sniffer.fallback_leasefile, "r");
	if (!fp) {
		// ENOENT is the expected case right after boot/reconnect, before
		// any DHCPv6 lease has ever been written -- not worth a log line
		// every time this runs. Anything else (permissions, etc.) is
		// genuinely unexpected and still worth reporting.
		if (errno != ENOENT) {
			syslog(LOG_WARNING, "pd-sniffer: fallback: cannot open %s: %s", sniffer.fallback_leasefile, strerror(errno));
		}
		return;
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
				return;
			}
			contents = tmp;
		}
		memcpy(contents + total, chunk, n);
		total += n;
	}
	fclose(fp);

	if (!contents) {
		syslog(LOG_WARNING, "pd-sniffer: fallback: %s is empty/unreadable", sniffer.fallback_leasefile);
		return;
	}
	contents[total] = 0;

	char *last = NULL;
	for (char *p = strstr(contents, "iaprefix"); p; p = strstr(p + 1, "iaprefix"))
		last = p;

	if (!last) {
		syslog(LOG_WARNING, "pd-sniffer: fallback: no iaprefix found in %s", sniffer.fallback_leasefile);
		free(contents);
		return;
	}

	char addrbuf[INET6_ADDRSTRLEN] = {0};
	unsigned int prefixlen = 0;

	if (sscanf(last, "iaprefix %45[0-9a-fA-F:]/%u", addrbuf, &prefixlen) != 2) {
		syslog(LOG_WARNING, "pd-sniffer: fallback: failed to parse iaprefix line: %.80s", last);
		free(contents);
		return;
	}

	struct in6_addr addr;
	if (inet_pton(AF_INET6, addrbuf, &addr) != 1) {
		syslog(LOG_WARNING, "pd-sniffer: fallback: invalid address in iaprefix: %s", addrbuf);
		free(contents);
		return;
	}

	if (prefixlen == 0 || prefixlen > 64) {
		syslog(LOG_WARNING, "pd-sniffer: fallback: unusable prefix length /%u in %s", prefixlen, addrbuf);
		free(contents);
		return;
	}

	char block[512] = {0};
	const char *end = strchr(last, '}');
	size_t blocklen = end ? (size_t)(end - last) : strlen(last);
	if (blocklen >= sizeof(block))
		blocklen = sizeof(block) - 1;
	memcpy(block, last, blocklen);

	uint32_t preferred, valid;
	pd_sniffer_fallback_parse_lifetimes(block, &preferred, &valid);

	syslog(LOG_NOTICE,
		"pd-sniffer: fallback: applying prefix %s/%u read from %s at "
		"startup (will be overwritten if a live DHCPv6 REPLY is captured)",
		addrbuf, prefixlen, sniffer.fallback_leasefile);

	pd_sniffer_apply_prefix(0, &addr, (uint8_t)prefixlen, preferred, valid);

	if (!pd_sniffer_dry_run) {
		struct relayd_interface *iface = sniffer.target_slave;
		iface->pd_addr_pending_len = 1;
		iface->pd_addr_pending_valid = true;
		iface->pd_watcher_managed = true;
		iface->pd_reconf = true;
	}

	free(contents);
}

int init_pd_sniffer(struct relayd_interface *wan_iface, struct relayd_interface *target_slave, const char *fallback_leasefile) {
	memset(&sniffer, 0, sizeof(sniffer));
	sniffer.wan_iface = wan_iface;
	sniffer.target_slave = target_slave;

	int sock = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(ETH_P_IPV6));
	if (sock < 0) {
		syslog(LOG_ERR, "pd-sniffer: unable to open packet socket: %s", strerror(errno));
		return -1;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_prog, sizeof(bpf_prog))) {
		syslog(LOG_ERR, "pd-sniffer: failed to set BPF: %s", strerror(errno));
		close(sock);
		return -1;
	}

	struct sockaddr_ll sll = {.sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_IPV6), .sll_ifindex = wan_iface->ifindex};
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll))) {
		syslog(LOG_ERR, "pd-sniffer: failed to bind to %s: %s", wan_iface->ifname, strerror(errno));
		close(sock);
		return -1;
	}

	sniffer.event.socket = sock;
	sniffer.event.handle_dgram = pd_sniffer_handle_packet;
	sniffer.event.handle_event = NULL;

	if (relayd_register_event(&sniffer.event)) {
		syslog(LOG_ERR, "pd-sniffer: failed to register with event loop");
		close(sock);
		return -1;
	}

	sniffer.addr_rtnl_socket = relayd_open_rtnl_socket();
	if (sniffer.addr_rtnl_socket < 0)
		syslog(LOG_WARNING,
			"pd-sniffer: failed to open rtnl socket, "
			"on-link address on %s will not be "
			"auto-configured (RAs will likely omit the "
			"delegated prefix)",
			target_slave->ifname);

	if (fallback_leasefile && fallback_leasefile[0]) {
		size_t flen = strlen(fallback_leasefile);
		if (flen >= sizeof(sniffer.fallback_leasefile)) {
			syslog(LOG_ERR, "pd-sniffer: fallback lease file path too long");
			close(sock);
			return -1;
		}
		memcpy(sniffer.fallback_leasefile, fallback_leasefile, flen + 1);

		// No more timerfd/wait here: waiting N seconds bought nothing --
		// the lease file is a static on-disk record that isn't going to
		// change just because we sat around for a while, so just try
		// reading it right now. Right after boot it commonly won't exist
		// yet (no lease has ever been seen); pd_sniffer_fallback_read()
		// treats that as an expected no-op, not a warning. If a live
		// DHCPv6 REPLY is captured later (see pd_sniffer_parse_reply()),
		// pd_sniffer_apply_prefix() there overwrites whatever this read
		// applied, same as before.
		pd_sniffer_fallback_read();
	}

	syslog(LOG_NOTICE, "pd-sniffer: sniffing DHCPv6 on %s for interface %s", wan_iface->ifname, target_slave->ifname);

	return 0;
}

void deinit_pd_sniffer(void) {
	if (!sniffer.target_slave)
		return; // init_pd_sniffer() was never called (-W not given)

	if (sniffer.have_applied_slave_addr)
		pd_sniffer_del_slave_address(sniffer.target_slave, &sniffer.applied_slave_addr);
}
