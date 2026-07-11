/**
 * Copyright (C) 2013 Steven Barth <steven@midlink.org>
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

#include "6relayd.h"
#include "dhcpv6.h"
#include "list.h"
#include "md5.h"

#include <alloca.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

struct assignment {
	struct list_head head;
	struct sockaddr_in6 peer;
	time_t valid_until;
	time_t reconf_sent;
	int reconf_cnt;
	char *hostname;
	uint8_t key[16];
	uint32_t na_hi; // upper 32 bits of the IA_NA (length==128) interface
	// identifier -- derived EUI-64, see derive_na_id().
	// Unused/zero for IA_PD (length <= 64) assignments,
	// whose subnet offset fits entirely in 'assigned'.
	uint32_t assigned;
	uint32_t iaid;
	uint8_t length; // length == 128 -> IA_NA, length <= 64 -> IA_PD
	bool accept_reconf;
	uint8_t clid_len;
	uint8_t clid_data[];
};

static const struct relayd_config *config = NULL;
static void update(struct relayd_interface *iface);
static void reconf_timer(struct relayd_event *event);
static void write_keyfile(void);
static void read_keyfile(void);
static struct relayd_event reconf_event = {-1, reconf_timer, NULL};
static int socket_fd = -1;
static uint32_t serial = 0;

int dhcpv6_init_ia(const struct relayd_config *relayd_config, int dhcpv6_socket) {
	config = relayd_config;
	socket_fd = dhcpv6_socket;

	reconf_event.socket = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	if (reconf_event.socket < 0) {
		syslog(LOG_ERR, "Failed to create timer: %s", strerror(errno));
		return -1;
	}

	relayd_register_event(&reconf_event);

	struct itimerspec its = {{2, 0}, {2, 0}};
	timerfd_settime(reconf_event.socket, 0, &its, NULL);

	for (size_t i = 0; i < config->slavecount; ++i) {
		struct relayd_interface *iface = &config->slaves[i];

		INIT_LIST_HEAD(&iface->pd_assignments);
		struct assignment *border = calloc(1, sizeof(*border));
		border->length = 64;
		list_add(&border->head, &iface->pd_assignments);
	}

	read_keyfile();

	for (size_t i = 0; i < config->slavecount; ++i)
		update(&config->slaves[i]);

	// Parse static entries
	for (size_t i = 0; i < config->dhcpv6_lease_len; ++i) {
		char *saveptr;
		char *duid = strtok_r(config->dhcpv6_lease[i], ":", &saveptr), *assign;
		size_t duidlen = (duid) ? strlen(duid) : 0;
		if (!duidlen || duidlen % 2 || !(assign = strtok_r(NULL, ":", &saveptr))) {
			syslog(LOG_ERR, "Invalid static lease %s", config->dhcpv6_lease[i]);
			return -1;
		}
		duidlen /= 2;

		// Construct entry
		struct assignment *a = calloc(1, sizeof(*a) + duidlen);
		a->clid_len = duidlen;
		a->length = 128;
		a->assigned = strtol(assign, NULL, 16);
		relayd_urandom(a->key, sizeof(a->key));

		for (size_t j = 0; j < duidlen; ++j) {
			char hexnum[3] = {duid[j * 2], duid[j * 2 + 1], 0};
			a->clid_data[j] = strtol(hexnum, NULL, 16);
		}

		// Assign to all interfaces
		struct assignment *c;
		for (size_t j = 0; j < config->slavecount; ++j) {
			struct relayd_interface *iface = &config->slaves[j];
			list_for_each_entry(c, &iface->pd_assignments, head) {
				if (c->length != 128 || c->assigned > a->assigned) {
					struct assignment *n = malloc(sizeof(*a) + duidlen);
					memcpy(n, a, sizeof(*a) + duidlen);
					list_add_tail(&n->head, &c->head);
				} else if (c->assigned == a->assigned) {
					// Already an assignment with that number
					break;
				}
			}
		}

		free(a);
	}

	return 0;
}

static time_t monotonic_time(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

static int send_reconf(struct relayd_interface *iface, struct assignment *assign) {
	struct {
		struct dhcpv6_client_header hdr;
		uint16_t srvid_type;
		uint16_t srvid_len;
		uint16_t duid_type;
		uint16_t hardware_type;
		uint8_t mac[6];
		uint16_t msg_type;
		uint16_t msg_len;
		uint8_t msg_id;
		struct dhcpv6_auth_reconfigure auth;
		uint16_t clid_type;
		uint16_t clid_len;
		uint8_t clid_data[128];
	} __attribute__((packed)) reconf_msg = {
		.hdr = {DHCPV6_MSG_RECONFIGURE, {0, 0, 0}},
		.srvid_type = htons(DHCPV6_OPT_SERVERID),
		.srvid_len = htons(10),
		.duid_type = htons(3),
		.hardware_type = htons(1),
		.mac = {iface->mac[0], iface->mac[1], iface->mac[2], iface->mac[3], iface->mac[4], iface->mac[5]},
		.msg_type = htons(DHCPV6_OPT_RECONF_MSG),
		.msg_len = htons(1),
		.msg_id = DHCPV6_MSG_RENEW,
		.auth = {htons(DHCPV6_OPT_AUTH), htons(sizeof(reconf_msg.auth) - 4), 3, 1, 0, {htonl(time(NULL)), htonl(++serial)}, 2, {0}},
		.clid_type = htons(DHCPV6_OPT_CLIENTID),
		.clid_len = htons(assign->clid_len),
		.clid_data = {0},
	};

	memcpy(reconf_msg.clid_data, assign->clid_data, assign->clid_len);
	struct iovec iov = {&reconf_msg, sizeof(reconf_msg) - 128 + assign->clid_len};

	md5_state_t md5;
	// HMAC-MD5 (RFC 2104) requires the key to be zero-padded up to the
	// hash's block size (64 bytes for MD5) before XORing with ipad/opad.
	// assign->key is only 16 bytes, so it must be extended into a 64-byte
	// buffer here -- using a bare 16-byte buffer (no padding) produces a
	// non-standard digest that a spec-compliant client (e.g. RouterOS)
	// will never reproduce, causing it to silently discard every
	// Reconfigure per RFC 3315 21.11 for failing authentication.
	uint8_t secretbytes[64];
	memset(secretbytes, 0, sizeof(secretbytes));
	memcpy(secretbytes, assign->key, sizeof(assign->key));

	for (size_t i = 0; i < sizeof(secretbytes); ++i)
		secretbytes[i] ^= 0x36;

	md5_init(&md5);
	md5_append(&md5, secretbytes, sizeof(secretbytes));
	md5_append(&md5, iov.iov_base, iov.iov_len);
	md5_finish(&md5, reconf_msg.auth.key);

	for (size_t i = 0; i < sizeof(secretbytes); ++i) {
		secretbytes[i] ^= 0x36;
		secretbytes[i] ^= 0x5c;
	}

	md5_init(&md5);
	md5_append(&md5, secretbytes, sizeof(secretbytes));
	md5_append(&md5, reconf_msg.auth.key, 16);
	md5_finish(&md5, reconf_msg.auth.key);

	ssize_t sent = relayd_forward_packet(socket_fd, &assign->peer, &iov, 1, iface);

	char peerbuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &assign->peer.sin6_addr, peerbuf, sizeof(peerbuf));
	if (sent < 0)
		syslog(LOG_WARNING, "send_reconf(%s): failed to send Reconfigure to %s: %s", iface->ifname, peerbuf, strerror(errno));
	else
		syslog(LOG_INFO, "send_reconf(%s): sent %zd byte Reconfigure to %s (reconf_cnt=%d)", iface->ifname, sent, peerbuf, assign->reconf_cnt);

	return sent;
}

static void write_statefile(void) {
	if (config->dhcpv6_statefile) {
		time_t now = monotonic_time(), wall_time = time(NULL);
		int fd = open(config->dhcpv6_statefile, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
		if (fd < 0) {
			return;
		}
		lockf(fd, F_LOCK, 0);
		if (ftruncate(fd, 0) < 0) {
			// Non-fatal: we still (re)write the file below, but if this
			// failed and the new content ends up shorter than whatever
			// was there before, stale trailing bytes would linger.
			syslog(LOG_WARNING, "write_statefile: ftruncate(%s) failed: %s", config->dhcpv6_statefile, strerror(errno));
		}

		FILE *fp = fdopen(fd, "w");
		if (!fp) {
			close(fd);
			return;
		}

		for (size_t i = 0; i < config->slavecount; ++i) {
			struct relayd_interface *iface = &config->slaves[i];

			struct assignment *c;
			list_for_each_entry(c, &iface->pd_assignments, head) {
				if (c->clid_len == 0)
					continue;

				char ipbuf[INET6_ADDRSTRLEN];
				char leasebuf[512];
				char duidbuf[264];
				const char hex[] = "0123456789abcdef";

				for (size_t i = 0; i < c->clid_len; ++i) {
					duidbuf[2 * i] = hex[(c->clid_data[i] >> 4) & 0x0f];
					duidbuf[2 * i + 1] = hex[c->clid_data[i] & 0x0f];
				}
				duidbuf[c->clid_len * 2] = 0;

				// iface DUID iaid hostname lifetime assigned length [addrs...]
				int l =
					snprintf(leasebuf, sizeof(leasebuf), "# %s %s %x %s %u %x %u ", iface->ifname, duidbuf, ntohl(c->iaid), (c->hostname ? c->hostname : "-"),
						(unsigned)(c->valid_until > now ? (c->valid_until - now + wall_time) : 0), c->assigned, (unsigned)c->length);

				struct in6_addr addr;
				for (size_t i = 0; i < iface->pd_addr_len; ++i) {
					if (iface->pd_addr[i].prefix > 64)
						continue;

					addr = iface->pd_addr[i].addr;
					if (c->length == 128) {
						addr.s6_addr32[2] = htonl(c->na_hi);
						addr.s6_addr32[3] = htonl(c->assigned);
					} else {
						addr.s6_addr32[1] |= htonl(c->assigned);
					}
					inet_ntop(AF_INET6, &addr, ipbuf, sizeof(ipbuf) - 1);

					if (c->length == 128 && c->hostname && i == 0)
						fprintf(fp, "%s\t%s\n", ipbuf, c->hostname);

					l += snprintf(leasebuf + l, sizeof(leasebuf) - l, "%s/%hhu ", ipbuf, c->length);
				}
				leasebuf[l - 1] = '\n';
				fwrite(leasebuf, 1, l, fp);
			}
		}

		fclose(fp);
	}

	if (config->dhcpv6_cb) {
		char *argv[2] = {config->dhcpv6_cb, NULL};
		if (!vfork()) {
			execv(argv[0], argv);
			_exit(128);
		}
	}
}

// Persists the Reconfigure key material (RFC 3315 21.4) for every live
// binding to a *separate* file from dhcpv6_statefile: that statefile is
// 0644 and meant for other tools to read (hostnames/leases), whereas this
// one contains raw HMAC-MD5 key material and must stay root-only. Without
// this, every 6relayd restart would forget the key it handed each client
// during their original Solicit/Request, and -- because that key is only
// ever (re)delivered on a fresh Solicit/Request, never on a Renew/Rebind --
// the client would keep the *old* key in memory with no way for us to ever
// send it a Reconfigure it can validate, until the client happens to redo
// a full Solicit/Request on its own (which can take a long time, since a
// well-behaved client has no reason to do that while its lease is still
// valid).
//
// Deliberately does NOT restore kernel routes here: restored assignments
// have no iface->pd_addr yet at startup (pd-lease-watcher/update() haven't
// run), so apply_lease() would set up routes against stale/absent prefix
// data. That happens naturally and correctly later, the first time the
// client's own Renew/Rebind/Request matches this restored binding.
static void write_keyfile(void) {
	if (!config->dhcpv6_statefile)
		return;

	char path[PATH_MAX];
	if ((size_t)snprintf(path, sizeof(path), "%s.keys", config->dhcpv6_statefile) >= sizeof(path))
		return;

	time_t now = monotonic_time(), wall_time = time(NULL);
	int fd = open(path, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
	if (fd < 0) {
		syslog(LOG_WARNING, "write_keyfile: open(%s) failed: %s", path, strerror(errno));
		return;
	}
	// Defensive: an inherited umask could still relax the mode passed to
	// open() above, and this file holds live key material.
	fchmod(fd, 0600);

	lockf(fd, F_LOCK, 0);
	if (ftruncate(fd, 0) < 0)
		syslog(LOG_WARNING, "write_keyfile: ftruncate(%s) failed: %s", path, strerror(errno));

	FILE *fp = fdopen(fd, "w");
	if (!fp) {
		close(fd);
		return;
	}

	for (size_t i = 0; i < config->slavecount; ++i) {
		struct relayd_interface *iface = &config->slaves[i];

		struct assignment *c;
		list_for_each_entry(c, &iface->pd_assignments, head) {
			if (c->clid_len == 0 || c->valid_until <= now)
				continue; // skip the border marker and anything already expired

			char duidbuf[264], keybuf[sizeof(c->key) * 2 + 1], peerbuf[sizeof(c->peer.sin6_addr) * 2 + 1];
			const char hex[] = "0123456789abcdef";

			for (size_t j = 0; j < c->clid_len; ++j) {
				duidbuf[2 * j] = hex[(c->clid_data[j] >> 4) & 0x0f];
				duidbuf[2 * j + 1] = hex[c->clid_data[j] & 0x0f];
			}
			duidbuf[c->clid_len * 2] = 0;

			for (size_t j = 0; j < sizeof(c->key); ++j) {
				keybuf[2 * j] = hex[(c->key[j] >> 4) & 0x0f];
				keybuf[2 * j + 1] = hex[c->key[j] & 0x0f];
			}
			keybuf[sizeof(c->key) * 2] = 0;

			// Persist the client's peer address too -- without it, a
			// restored binding has an all-zero (unspecified, "::") peer
			// until the client's next real packet updates it, and any
			// Reconfigure attempted before that fails outright ("Destination
			// address required"). Scope id is intentionally NOT persisted:
			// it's an interface index, which can differ across a restart
			// (or even just be plain wrong if read back verbatim on a
			// system where indices got renumbered) -- read_keyfile()
			// re-derives it from the interface actually matched by name.
			for (size_t j = 0; j < sizeof(c->peer.sin6_addr); ++j) {
				peerbuf[2 * j] = hex[(c->peer.sin6_addr.s6_addr[j] >> 4) & 0x0f];
				peerbuf[2 * j + 1] = hex[c->peer.sin6_addr.s6_addr[j] & 0x0f];
			}
			peerbuf[sizeof(c->peer.sin6_addr) * 2] = 0;

			// ifname DUID iaid length assigned na_hi accept_reconf lifetime key peer_addr peer_port hostname
			//
			// na_hi is the upper 32 bits of the IA_NA interface identifier
			// (see struct assignment); always 0 and harmless to round-trip
			// for IA_PD entries. Field added here -- .keys files written
			// by older builds have 11 fields, not 12, so the fscanf() loop
			// below simply won't match them and those entries are skipped
			// (same convention as the earlier 9->11 field bump).
			fprintf(fp, "%s %s %x %hhu %x %x %d %u %s %s %u %s\n", iface->ifname, duidbuf, ntohl(c->iaid), c->length, c->assigned, c->na_hi,
				c->accept_reconf ? 1 : 0, (unsigned)(c->valid_until - now + wall_time), keybuf, peerbuf, ntohs(c->peer.sin6_port),
				(c->hostname ? c->hostname : "-"));
		}
	}

	fclose(fp);
}

// Counterpart to write_keyfile(), read back once at startup (before the
// first update() call) so bindings created before a 6relayd restart keep
// working -- both the Renew/Rebind lookup (so we don't bounce the client
// with NOBINDING and force it through a full Solicit/Request) and the
// Reconfigure key itself (see write_keyfile() for why that key can only
// ever be delivered fresh during a Solicit/Request).
static void read_keyfile(void) {
	if (!config->dhcpv6_statefile)
		return;

	char path[PATH_MAX];
	if ((size_t)snprintf(path, sizeof(path), "%s.keys", config->dhcpv6_statefile) >= sizeof(path))
		return;

	FILE *fp = fopen(path, "r");
	if (!fp)
		return; // nothing persisted yet (first run, or feature unused) -- not an error

	time_t now = monotonic_time(), wall_time = time(NULL);
	char ifname[16], duidbuf[264], keybuf[264], peerbuf[64], hostname[256];
	unsigned iaid, assigned, na_hi, lifetime, peer_port;
	unsigned length_u, accept_reconf_u;
	int restored = 0;

	while (fscanf(fp, "%15s %263s %x %u %x %x %u %u %263s %63s %u %255s\n", ifname, duidbuf, &iaid, &length_u, &assigned, &na_hi, &accept_reconf_u, &lifetime,
			   keybuf, peerbuf, &peer_port, hostname) == 12) {
		size_t duidlen = strlen(duidbuf) / 2;
		size_t keylen = strlen(keybuf) / 2;
		size_t peerlen = strlen(peerbuf) / 2;
		if (duidlen == 0 || duidlen > 130 || keylen != 16 || peerlen != 16)
			continue; // malformed line -- skip rather than abort the whole restore

		struct relayd_interface *iface = NULL;
		for (size_t i = 0; i < config->slavecount; ++i) {
			if (!strcmp(config->slaves[i].ifname, ifname)) {
				iface = &config->slaves[i];
				break;
			}
		}
		if (!iface)
			continue; // interface renamed/removed since this was written

		// lifetime==0 means write_keyfile() already saw this as expired
		// (or expiring right at write time) -- a stale key for a lease
		// that's gone is of no use, so don't resurrect it.
		time_t valid_until = (time_t)lifetime - wall_time + now;
		if (lifetime == 0 || valid_until <= now)
			continue;

		struct assignment *a = calloc(1, sizeof(*a) + duidlen);
		if (!a)
			continue;
		a->clid_len = duidlen;
		a->iaid = htonl(iaid);
		a->length = (uint8_t)length_u;
		a->assigned = assigned;
		a->na_hi = na_hi;
		a->accept_reconf = accept_reconf_u != 0;
		a->valid_until = valid_until;
		if (strcmp(hostname, "-")) {
			a->hostname = strdup(hostname);
		}

		for (size_t j = 0; j < duidlen; ++j) {
			char hexnum[3] = {duidbuf[j * 2], duidbuf[j * 2 + 1], 0};
			a->clid_data[j] = (uint8_t)strtol(hexnum, NULL, 16);
		}
		for (size_t j = 0; j < sizeof(a->key); ++j) {
			char hexnum[3] = {keybuf[j * 2], keybuf[j * 2 + 1], 0};
			a->key[j] = (uint8_t)strtol(hexnum, NULL, 16);
		}
		for (size_t j = 0; j < sizeof(a->peer.sin6_addr); ++j) {
			char hexnum[3] = {peerbuf[j * 2], peerbuf[j * 2 + 1], 0};
			a->peer.sin6_addr.s6_addr[j] = (uint8_t)strtol(hexnum, NULL, 16);
		}
		a->peer.sin6_family = AF_INET6;
		a->peer.sin6_port = htons((uint16_t)peer_port);
		a->peer.sin6_scope_id = iface->ifindex;

		// Insert sorted by 'assigned', same convention assign_pd() uses
		// (list_add_tail(&assign->head, &border->head) as the fallback) --
		// the border marker must stay the last entry in the list, since
		// update() fetches it via list_last_entry().
		struct assignment *border = list_last_entry(&iface->pd_assignments, struct assignment, head);
		struct assignment *c, *inserted_before = NULL;
		bool duplicate = false;
		list_for_each_entry(c, &iface->pd_assignments, head) {
			if (c == border)
				break;
			if (c->length == a->length && c->assigned == a->assigned && c->na_hi == a->na_hi) {
				duplicate = true; // shouldn't happen, but don't double-insert
				break;
			}
			if (c->assigned > a->assigned) {
				inserted_before = c;
				break;
			}
		}
		if (duplicate) {
			free(a->hostname);
			free(a);
		} else {
			list_add_tail(&a->head, inserted_before ? &inserted_before->head : &border->head);
			++restored;
		}
	}

	fclose(fp);

	if (restored)
		syslog(LOG_NOTICE, "dhcpv6-ia: restored %d client binding(s)/Reconfigure key(s) from %s", restored, path);
}

static void apply_lease(struct relayd_interface *iface, struct assignment *a, bool add) {
	if (a->length > 64)
		return;

	for (size_t i = 0; i < iface->pd_addr_len; ++i) {
		struct in6_addr prefix = iface->pd_addr[i].addr;
		prefix.s6_addr32[1] |= htonl(a->assigned);
		relayd_setup_route(&prefix, a->length, iface, &a->peer.sin6_addr, add);
	}
}

static bool assign_pd(struct relayd_interface *iface, struct assignment *assign) {
	struct assignment *c;
	if (iface->pd_addr_len < 1)
		return false;

	// Fast path: nothing else is currently handed out of this pool, so
	// give the whole delegated block to this client (offset 0, full
	// length), skipping the alignment/reservation math below entirely.
	// That math always rounds the starting offset up to reserve room
	// for our own on-link address, which makes it structurally
	// incapable of ever satisfying a request for the *whole* pool in
	// one shot -- exactly the case of a single downstream router asking
	// for the full /56 we got delegated.
	//
	// Deliberately IGNORE the client's hinted length here as long as the
	// pool is free: a MikroTik (or any other single downstream router)
	// that has "Prefix Hint = ::/64" configured will ask for a /64
	// (assign->length == 64), which is numerically *more specific* than
	// our /56 delegation (iface->pd_addr[0].prefix == 56), so a
	// "hint <= delegated" check never lets it through and it falls into
	// the old split logic below, which reserves offset 0 for us and
	// hands out offset 1 (a single /64 sub-slice) instead of the /56.
	// Since we're only doing this when no other real client already has
	// an assignment, there's no sub-delegation to protect yet, so it's
	// safe -- and correct for this single-router topology -- to just
	// give the whole pool regardless of what length was hinted.
	{
		struct assignment *border = list_last_entry(&iface->pd_assignments, struct assignment, head);
		bool pool_free = true;
		list_for_each_entry(c, &iface->pd_assignments, head) {
			// Only an existing *prefix* delegation (length <= 64) really
			// consumes pool space. IA_NA address assignments (length ==
			// 128) always sit on the base /64 (offset 0) regardless of
			// how the PD pool gets split, so they must NOT be treated as
			// occupying the pool -- otherwise a client that sends both an
			// IA_NA and an IA_PD in the same message (e.g. a MikroTik with
			// "Request Address" + Prefix Delegation both enabled) has its
			// own IA_NA binding (added to this same list by assign_na()
			// just before we get here, since IAs in a message are
			// processed in order) mistaken for pool contention. That
			// falsely disables this fast path, forcing the split logic
			// below instead, which reserves offset 0 and hands out offset
			// 1 -- i.e. the PD ends up delegated on a different /64 (e.g.
			// f101::/64) than the client's own IA_NA address (e.g.
			// f100::fd5), even though nothing else is actually using the
			// pool yet.
			if (c->clid_len != 0 && c != assign && c->length <= 64) { // real PD assignment, not the border marker or an NA address
				pool_free = false;
				break;
			}
		}

		if (pool_free) {
			assign->length = iface->pd_addr[0].prefix;
			assign->assigned = 0;
			list_add_tail(&assign->head, &border->head);
			apply_lease(iface, assign, true);
			return true;
		}
	}

	// Try honoring the hint first
	uint32_t current = 1, asize = (1 << (64 - assign->length)) - 1;
	if (assign->assigned) {
		list_for_each_entry(c, &iface->pd_assignments, head) {
			if (c->length == 128)
				continue;

			if (assign->assigned >= current && assign->assigned + asize < c->assigned) {
				list_add_tail(&assign->head, &c->head);
				apply_lease(iface, assign, true);
				return true;
			}

			if (c->assigned != 0)
				current = (c->assigned + (1 << (64 - c->length)));
		}
	}

	// Fallback to a variable assignment
	current = 1;
	list_for_each_entry(c, &iface->pd_assignments, head) {
		if (c->length == 128)
			continue;

		current = (current + asize) & (~asize);
		if (current + asize < c->assigned) {
			assign->assigned = current;
			list_add_tail(&assign->head, &c->head);
			apply_lease(iface, assign, true);
			return true;
		}

		if (c->assigned != 0)
			current = (c->assigned + (1 << (64 - c->length)));
	}

	return false;
}

// DUID types (RFC 3315 sec. 9) and the ARP hardware-type value for
// Ethernet (IANA "ARP Hardware Types" registry, type 1) as carried in
// DUID-LLT/DUID-LL.
#define DHCPV6_DUID_LLT 1
#define DHCPV6_DUID_LL 3
#define DHCPV6_HWTYPE_ETHER 1

// Derive a stable, non-random 64-bit interface identifier for an IA_NA
// assignment straight from the client's own DUID -- no relay-invented
// offset. If the DUID is DUID-LLT or DUID-LL over Ethernet (the common
// case for basically every real client, MikroTik included), this is a
// real modified EUI-64 built from the client's actual MAC, i.e. exactly
// what SLAAC would have produced on that client for the same /64. Any
// other DUID type (EN/vendor, UUID, ...) carries no link-layer address
// to derive from, so we fall back to a deterministic hash of the whole
// DUID -- still 100% reproducible per-client across restarts, just not
// a "real" EUI-64.
static void derive_na_id(const struct assignment *assign, uint32_t *hi, uint32_t *lo) {
	const uint8_t *clid = assign->clid_data;
	size_t len = assign->clid_len;

	if (len >= 14 && clid[0] == 0 && clid[1] == DHCPV6_DUID_LLT && clid[2] == 0 && clid[3] == DHCPV6_HWTYPE_ETHER) {
		// DUID-LLT: type(2) hwtype(2) time(4) mac(6)
		const uint8_t *mac = clid + 8;
		*hi = ((uint32_t)(mac[0] ^ 0x02) << 24) | ((uint32_t)mac[1] << 16) | ((uint32_t)mac[2] << 8) | 0xff;
		*lo = (0xfeu << 24) | ((uint32_t)mac[3] << 16) | ((uint32_t)mac[4] << 8) | mac[5];
		return;
	}

	if (len >= 10 && clid[0] == 0 && clid[1] == DHCPV6_DUID_LL && clid[2] == 0 && clid[3] == DHCPV6_HWTYPE_ETHER) {
		// DUID-LL: type(2) hwtype(2) mac(6)
		const uint8_t *mac = clid + 4;
		*hi = ((uint32_t)(mac[0] ^ 0x02) << 24) | ((uint32_t)mac[1] << 16) | ((uint32_t)mac[2] << 8) | 0xff;
		*lo = (0xfeu << 24) | ((uint32_t)mac[3] << 16) | ((uint32_t)mac[4] << 8) | mac[5];
		return;
	}

	// Fallback: FNV-1a 64-bit over the raw DUID bytes. Deterministic --
	// same DUID always hashes to the same id -- just not a real EUI-64.
	uint64_t h = 0xcbf29ce484222325ULL;
	for (size_t i = 0; i < len; ++i) {
		h ^= clid[i];
		h *= 0x100000001b3ULL;
	}
	*hi = (uint32_t)(h >> 32);
	*lo = (uint32_t)h;
}

static bool assign_na(struct relayd_interface *iface, struct assignment *assign) {
	if (iface->pd_addr_len < 1)
		return false;

	uint32_t hi, lo;
	derive_na_id(assign, &hi, &lo);

	// Collision handling: with a real EUI-64 this should never trigger
	// (each client's MAC is unique on the segment). Kept anyway to cover
	// the hashed fallback path and any genuinely misbehaving client that
	// sends someone else's DUID. Perturb deterministically (increment)
	// rather than reroll something random.
	for (size_t i = 0; i < 100; ++i) {
		struct assignment *c;
		bool taken = false;
		list_for_each_entry(c, &iface->pd_assignments, head) {
			if (c->length == 128 && c->na_hi == hi && c->assigned == lo) {
				taken = true;
				break;
			}
		}

		if (!taken) {
			struct assignment *last = list_last_entry(&iface->pd_assignments, struct assignment, head);
			assign->na_hi = hi;
			assign->assigned = lo;
			list_add_tail(&assign->head, &last->head);
			return true;
		}

		++lo; // deterministic perturbation, not a fresh random draw
	}

	return false;
}

static int prefixcmp(const void *va, const void *vb) {
	const struct relayd_ipaddr *a = va, *b = vb;
	uint32_t a_pref = ((a->addr.s6_addr[0] & 0xfe) != 0xfc) ? a->preferred : 1;
	uint32_t b_pref = ((b->addr.s6_addr[0] & 0xfe) != 0xfc) ? b->preferred : 1;
	return (a_pref < b_pref) ? 1 : (a_pref > b_pref) ? -1 : 0;
}

static void update(struct relayd_interface *iface) {
	struct relayd_ipaddr addr[8];
	memset(addr, 0, sizeof(addr));
	int len;

	// TODO(pd-lease-watcher): iface->pd_watcher_managed is the
	// persistent counterpart of pd_reconf -- see the comment on it in
	// 6relayd.h for why pd_reconf alone (one-shot, also written by
	// ndp.c) can't gate this safely across every call site of
	// update(), including the packet-driven one below.
	bool from_watcher = iface->pd_watcher_managed;

	if (from_watcher && iface->pd_addr_pending_valid) {
		// The watcher has a newly-parsed prefix waiting that we haven't
		// diffed against pd_addr[] yet -- consume it now, exactly once,
		// so the change-detection below compares genuinely new data
		// against the last-committed state (mirrors the netlink path,
		// where the fresh read and pd_addr[] are two distinct arrays).
		// Do NOT read from iface->pd_addr here: it still holds the
		// *previous* commit at this point, which is exactly what we
		// want to diff against further down.
		len = (int)iface->pd_addr_pending_len;
		if (len > 8)
			len = 8;
		memcpy(addr, iface->pd_addr_pending, len * sizeof(*addr));
		iface->pd_addr_pending_valid = false;
	} else if (from_watcher) {
		// No new data since the last call (e.g. this update() run was
		// triggered by an unrelated client packet, not a lease-file
		// change): just re-run the relativize/commit dance on the
		// already-committed state below. Comparing it against itself
		// is intentionally a no-op here -- there is nothing new to
		// detect a change from.
		len = (int)iface->pd_addr_len;
		if (len > 8)
			len = 8;
		memcpy(addr, iface->pd_addr, len * sizeof(*addr));
	} else {
		len = relayd_get_interface_addresses(iface->ifindex, addr, 8);

		if (len < 0)
			return;
	}

	qsort(addr, len, sizeof(*addr), prefixcmp);

	time_t now = monotonic_time();
	int minprefix = -1;

	if (from_watcher) {
		// The array we just copied above (whether from pd_addr_pending[]
		// or, on a no-new-data call, from pd_addr[] itself) holds
		// lifetimes already made absolute (i.e. converted to a fixed
		// point on the monotonic clock) by pd-lease-watcher.c right
		// after parsing the lease file, or by a *previous* run of this
		// same block. Undo that here by subtracting the current time so
		// the "+= now" pass a few lines down turns it back into an
		// absolute deadline that hasn't drifted, exactly like a fresh
		// netlink read would produce.
		//
		// NOTE: this must subtract `now`, not "elapsed since the last
		// call" -- the stored value is an absolute deadline, not a
		// relative duration, so elapsed-based subtraction effectively
		// added the previous call's timestamp back in every time this
		// ran, making preferred/valid balloon further into the future
		// on every single DHCPv6 packet and every 2s reconf tick.
		for (int i = 0; i < len; ++i) {
			addr[i].preferred = (addr[i].preferred > (uint32_t)now) ? addr[i].preferred - (uint32_t)now : 0;
			addr[i].valid = (addr[i].valid > (uint32_t)now) ? addr[i].valid - (uint32_t)now : 0;
		}
	}

	for (int i = 0; i < len; ++i) {
		if (addr[i].prefix > minprefix)
			minprefix = addr[i].prefix;

		addr[i].addr.s6_addr32[2] = 0;
		addr[i].addr.s6_addr32[3] = 0;

		if (addr[i].preferred < UINT32_MAX - now)
			addr[i].preferred += now;

		if (addr[i].valid < UINT32_MAX - now)
			addr[i].valid += now;
	}

	if (from_watcher)
		iface->pd_addr_applied_at = now;

	struct assignment *border = list_last_entry(&iface->pd_assignments, struct assignment, head);
	// minprefix stays -1 when len == 0 (no usable prefix right now -- e.g.
	// pd-lease-watcher just invalidated the delegation). "1 << (64 - (-1))"
	// would be a 65-bit shift, which is undefined behavior; there's no
	// prefix space to hand out anyway, so just say so.
	border->assigned = (minprefix >= 0) ? (1U << (64 - minprefix)) : 0;

	bool change = len != (int)iface->pd_addr_len;
	for (int i = 0; !change && i < len; ++i) {
		if (addr[i].addr.s6_addr32[0] != iface->pd_addr[i].addr.s6_addr32[0] || addr[i].addr.s6_addr32[1] != iface->pd_addr[i].addr.s6_addr32[1] ||
			(addr[i].preferred > 0) != (iface->pd_addr[i].preferred > 0) ||
			(addr[i].valid > (uint32_t)now + 7200) != (iface->pd_addr[i].valid > (uint32_t)now + 7200))
			change = true;
	}

	if (change)
		syslog(LOG_INFO, "update(%s): prefix change detected (%zu -> %d addr(es)), evaluating reconfigure for assignments", iface->ifname, iface->pd_addr_len,
			len);

	if (change && iface->pd_addr_len > 0) {
		// Snapshot the outgoing delegation's base *before* it's
		// overwritten below -- this is what already-bound clients were
		// actually told, and is what an explicit invalidation reply
		// (valid=0/preferred=0) built during the gap before the new
		// delegation lands needs to match exactly.
		iface->last_pd_addr = iface->pd_addr[0];
		iface->last_pd_addr_valid = true;
	}

	if (change) {
		struct assignment *c;
		list_for_each_entry(c, &iface->pd_assignments, head) if (c != border) apply_lease(iface, c, false);
	}

	memcpy(iface->pd_addr, addr, len * sizeof(*addr));
	iface->pd_addr_len = len;

	if (change) { // Addresses / prefixes have changed
		struct list_head reassign = LIST_HEAD_INIT(reassign);
		struct assignment *c, *d;
		list_for_each_entry_safe(c, d, &iface->pd_assignments, head) {
			if (c->clid_len == 0)
				continue;

			if (c->valid_until < now) {
				syslog(LOG_INFO, "update(%s): NOT considering assignment (iaid=%08x) for reconfigure: valid_until (%ld) already in the past (now=%ld)",
					iface->ifname, ntohl(c->iaid), (long)c->valid_until, (long)now);
				continue;
			}

			if (c->length < 128 && c->assigned >= border->assigned && c != border)
				list_move(&c->head, &reassign);
			else if (c != border)
				apply_lease(iface, c, true);

			if (c->accept_reconf && c->reconf_cnt == 0) {
				c->reconf_cnt = 1;
				c->reconf_sent = now;
				syslog(LOG_NOTICE, "update(%s): sending Reconfigure (iaid=%08x, length=%u)", iface->ifname, ntohl(c->iaid), c->length);
				send_reconf(iface, c);

				// Leave all other assignments of that client alone
				struct assignment *a;
				list_for_each_entry(a, &iface->pd_assignments,
					head) if (a != c && a->clid_len == c->clid_len && !memcmp(a->clid_data, c->clid_data, a->clid_len)) c->reconf_cnt = INT_MAX;
			} else if (!c->accept_reconf) {
				syslog(LOG_INFO, "update(%s): NOT sending Reconfigure (iaid=%08x): client never sent Reconfigure Accept (option 20)", iface->ifname,
					ntohl(c->iaid));
			} else if (c->reconf_cnt != 0) {
				syslog(LOG_INFO, "update(%s): NOT sending Reconfigure (iaid=%08x): one already in flight (reconf_cnt=%d)", iface->ifname, ntohl(c->iaid),
					c->reconf_cnt);
			}
		}

		while (!list_empty(&reassign)) {
			c = list_first_entry(&reassign, struct assignment, head);
			list_del(&c->head);
			if (!assign_pd(iface, c)) {
				c->assigned = 0;
				list_add(&c->head, &iface->pd_assignments);
			}
		}

		write_statefile();
		write_keyfile();
	}
}

static void reconf_timer(struct relayd_event *event) {
	uint64_t cnt;
	if (read(event->socket, &cnt, sizeof(cnt))) {
		// Avoid compiler warning
	}

	time_t now = monotonic_time();
	for (size_t i = 0; i < config->slavecount; ++i) {
		struct relayd_interface *iface = &config->slaves[i];
		if (iface->pd_assignments.next == NULL)
			return;

		struct assignment *a, *n;
		list_for_each_entry_safe(a, n, &iface->pd_assignments, head) {
			if (a->valid_until < now) {
				if ((a->length < 128 && a->clid_len > 0) || (a->length == 128 && a->clid_len == 0)) {
					list_del(&a->head);
					free(a->hostname);
					free(a);
				}
			} else if (a->reconf_cnt > 0 && a->reconf_cnt < 8 && now > a->reconf_sent + (1 << a->reconf_cnt)) {
				++a->reconf_cnt;
				a->reconf_sent = now;
				send_reconf(iface, a);
			}
		}

		if (iface->pd_reconf) {
			update(iface);
			iface->pd_reconf = false;
		}
	}
}

static size_t append_reply(
	uint8_t *buf, size_t buflen, uint16_t status, const struct dhcpv6_ia_hdr *ia, struct assignment *a, struct relayd_interface *iface, bool request) {
	if (buflen < sizeof(*ia) + sizeof(struct dhcpv6_ia_prefix))
		return 0;

	struct dhcpv6_ia_hdr out = {ia->type, 0, ia->iaid, 0, 0};
	size_t datalen = sizeof(out);
	time_t now = monotonic_time();

	if (status) {
		struct __attribute__((packed)) {
			uint16_t type;
			uint16_t len;
			uint16_t value;
		} stat = {htons(DHCPV6_OPT_STATUS), htons(sizeof(stat) - 4), htons(status)};

		memcpy(buf + datalen, &stat, sizeof(stat));
		datalen += sizeof(stat);
	} else {
		if (a) {
			uint32_t pref = 3600;
			uint32_t valid = 3600;
			bool have_non_ula = false;
			for (size_t i = 0; i < iface->pd_addr_len; ++i)
				if ((iface->pd_addr[i].addr.s6_addr[0] & 0xfe) != 0xfc)
					have_non_ula = true;

			for (size_t i = 0; i < iface->pd_addr_len; ++i) {
				uint32_t prefix_pref = iface->pd_addr[i].preferred - now;
				uint32_t prefix_valid = iface->pd_addr[i].valid - now;

				if (iface->pd_addr[i].prefix > 64 || iface->pd_addr[i].preferred <= (uint32_t)now)
					continue;

				// ULA-deprecation compatibility workaround
				if ((iface->pd_addr[i].addr.s6_addr[0] & 0xfe) == 0xfc && a->length == 128 && have_non_ula && config->deprecate_ula_if_public_avail)
					continue;

				if (prefix_pref > 86400)
					prefix_pref = 86400;

				if (prefix_valid > 86400)
					prefix_valid = 86400;

				if (a->length < 128) {
					struct dhcpv6_ia_prefix p = {.type = htons(DHCPV6_OPT_IA_PREFIX),
						.len = htons(sizeof(p) - 4),
						.preferred = htonl(prefix_pref),
						.valid = htonl(prefix_valid),
						.prefix = a->length,
						.addr = iface->pd_addr[i].addr};
					p.addr.s6_addr32[1] |= htonl(a->assigned);

					// NOTE: unlike the IA_ADDR/NA branch below, assigned == 0
					// is a *valid* offset here -- it's what the assign_pd()
					// fast-path uses to hand out the entire delegated block
					// (e.g. the whole /56) to a single downstream router, so
					// it must not be treated as "nothing assigned".
					if (datalen + sizeof(p) > buflen)
						continue;

					memcpy(buf + datalen, &p, sizeof(p));
					datalen += sizeof(p);
				} else {
					struct dhcpv6_ia_addr n = {.type = htons(DHCPV6_OPT_IA_ADDR),
						.len = htons(sizeof(n) - 4),
						.addr = iface->pd_addr[i].addr,
						.preferred = htonl(prefix_pref),
						.valid = htonl(prefix_valid)};
					n.addr.s6_addr32[2] = htonl(a->na_hi);
					n.addr.s6_addr32[3] = htonl(a->assigned);

					if (datalen + sizeof(n) > buflen || a->assigned == 0)
						continue;

					memcpy(buf + datalen, &n, sizeof(n));
					datalen += sizeof(n);
				}

				// Calculate T1 / T2 based on non-deprecated addresses
				if (prefix_pref > 0) {
					if (prefix_pref < pref)
						pref = prefix_pref;

					if (prefix_valid < valid)
						valid = prefix_valid;
				}
			}

			a->valid_until = valid + now;
			out.t1 = htonl(pref * 5 / 10);
			out.t2 = htonl(pref * 8 / 10);

			if (!out.t1)
				out.t1 = htonl(1);

			if (!out.t2)
				out.t2 = htonl(1);
		}

		if (!request) {
			uint8_t *odata, *end = ((uint8_t *)ia) + htons(ia->len) + 4;
			uint16_t otype, olen;
			dhcpv6_for_each_option((uint8_t *)&ia[1], end, otype, olen, odata) {
				struct dhcpv6_ia_prefix *p = (struct dhcpv6_ia_prefix *)&odata[-4];
				struct dhcpv6_ia_addr *n = (struct dhcpv6_ia_addr *)&odata[-4];
				if ((otype != DHCPV6_OPT_IA_PREFIX || olen < sizeof(*p) - 4) && (otype != DHCPV6_OPT_IA_ADDR || olen < sizeof(*n) - 4))
					continue;

				bool found = false;
				if (a) {
					for (size_t i = 0; i < iface->pd_addr_len; ++i) {
						if (iface->pd_addr[i].prefix > 64 || iface->pd_addr[i].preferred <= (uint32_t)now)
							continue;

						struct in6_addr addr = iface->pd_addr[i].addr;
						if (ia->type == htons(DHCPV6_OPT_IA_PD)) {
							addr.s6_addr32[1] |= htonl(a->assigned);

							struct in6_addr p_addr = p->addr;
							if (IN6_ARE_ADDR_EQUAL(&p_addr, &addr) && p->prefix == a->length)
								found = true;
						} else {
							addr.s6_addr32[2] = htonl(a->na_hi);
							addr.s6_addr32[3] = htonl(a->assigned);

							struct in6_addr n_addr = n->addr;
							if (IN6_ARE_ADDR_EQUAL(&n_addr, &addr))
								found = true;
						}
					}
				}

				if (!found) {
					if (otype == DHCPV6_OPT_IA_PREFIX) {
						struct dhcpv6_ia_prefix inv = {.type = htons(DHCPV6_OPT_IA_PREFIX),
							.len = htons(sizeof(inv) - 4),
							.preferred = 0,
							.valid = 0,
							.prefix = p->prefix,
							.addr = p->addr};

						if (datalen + sizeof(inv) > buflen)
							continue;

						memcpy(buf + datalen, &inv, sizeof(inv));
						datalen += sizeof(inv);
					} else {
						struct dhcpv6_ia_addr inv = {
							.type = htons(DHCPV6_OPT_IA_ADDR), .len = htons(sizeof(inv) - 4), .addr = n->addr, .preferred = 0, .valid = 0};

						if (datalen + sizeof(inv) > buflen)
							continue;

						memcpy(buf + datalen, &inv, sizeof(inv));
						datalen += sizeof(inv);
					}
				}
			}
		}
	}

	out.len = htons(datalen - 4);
	memcpy(buf, &out, sizeof(out));
	return datalen;
}

// Build a Reply IA that explicitly invalidates (preferred=valid=0) exactly
// the prefix/address the client currently believes it holds, reconstructed
// from the assignment's own fields (a->assigned/a->length or a->na_hi)
// combined with iface->last_pd_addr -- the last delegation base that was
// actually committed before the change that made 'a' unusable. This is the
// real RFC 3315/3633 signal for "stop using this now": unlike a bare status
// code (no address/prefix option at all) or staying silent (indistinguishable
// from packet loss to the client), a client seeing its own binding come back
// with valid=0 has no ambiguity and should remove the associated routes
// immediately. Falls back to "nothing to send" (returns 0) if we never
// actually had a delegation to snapshot.
static size_t append_invalidate_reply(
	uint8_t *buf, size_t buflen, const struct dhcpv6_ia_hdr *ia, const struct assignment *a, const struct relayd_interface *iface) {
	if (!iface->last_pd_addr_valid)
		return 0;

	size_t need = sizeof(struct dhcpv6_ia_hdr) + ((a->length < 128) ? sizeof(struct dhcpv6_ia_prefix) : sizeof(struct dhcpv6_ia_addr));
	if (buflen < need)
		return 0;

	struct dhcpv6_ia_hdr out = {ia->type, 0, ia->iaid, 0, 0};
	size_t datalen = sizeof(out);

	if (a->length < 128) {
		struct in6_addr prefix = iface->last_pd_addr.addr;
		prefix.s6_addr32[1] |= htonl(a->assigned);
		struct dhcpv6_ia_prefix p = {
			.type = htons(DHCPV6_OPT_IA_PREFIX), .len = htons(sizeof(p) - 4), .preferred = 0, .valid = 0, .prefix = a->length, .addr = prefix};
		memcpy(buf + datalen, &p, sizeof(p));
		datalen += sizeof(p);
	} else {
		struct in6_addr addr = iface->last_pd_addr.addr;
		addr.s6_addr32[2] = htonl(a->na_hi);
		addr.s6_addr32[3] = htonl(a->assigned);
		struct dhcpv6_ia_addr n = {.type = htons(DHCPV6_OPT_IA_ADDR), .len = htons(sizeof(n) - 4), .addr = addr, .preferred = 0, .valid = 0};
		memcpy(buf + datalen, &n, sizeof(n));
		datalen += sizeof(n);
	}

	out.len = htons(datalen - 4);
	memcpy(buf, &out, sizeof(out));
	return datalen;
}

size_t dhcpv6_handle_ia(uint8_t *buf, size_t buflen, struct relayd_interface *iface, const struct sockaddr_in6 *addr, const void *data, const uint8_t *end) {
	time_t now = monotonic_time();
	size_t response_len = 0;
	const struct dhcpv6_client_header *hdr = data;
	uint8_t *start = (uint8_t *)&hdr[1], *odata;
	uint16_t otype, olen;

	// Find and parse client-id and hostname
	bool accept_reconf = false;
	uint8_t *clid_data = NULL, clid_len = 0;
	char hostname[256];
	size_t hostname_len = 0;
	dhcpv6_for_each_option(start, end, otype, olen, odata) {
		if (otype == DHCPV6_OPT_CLIENTID) {
			clid_data = odata;
			clid_len = olen;
		} else if (otype == DHCPV6_OPT_FQDN && olen >= 2 && olen <= 255) {
			uint8_t fqdn_buf[256];
			memcpy(fqdn_buf, odata, olen);
			fqdn_buf[olen++] = 0;

			if (dn_expand(&fqdn_buf[1], &fqdn_buf[olen], &fqdn_buf[1], hostname, sizeof(hostname)) > 0)
				hostname_len = strcspn(hostname, ".");
		} else if (otype == DHCPV6_OPT_RECONF_ACCEPT) {
			accept_reconf = true;
		}
	}

	// 128, not 130: send_reconf() below copies clid_data into a fixed
	// 128-byte struct field (reconf_msg.clid_data) when it later sends a
	// Reconfigure to this client -- a clid_len of 129/130 would overflow
	// that copy by up to 2 bytes. (dhcpv6.c's equivalent check uses 130
	// because *that* file's clientid_buf really is 130 bytes; this one
	// isn't, so it needs its own, tighter bound.)
	if (!clid_data || !clid_len || clid_len > 128)
		goto out;

	update(iface);
	bool update_state = false;

	struct assignment *first = NULL;
	dhcpv6_for_each_option(start, end, otype, olen, odata) {
		bool is_pd = (otype == DHCPV6_OPT_IA_PD);
		bool is_na = (otype == DHCPV6_OPT_IA_NA);
		if (!is_pd && !is_na)
			continue;

		struct dhcpv6_ia_hdr *ia = (struct dhcpv6_ia_hdr *)&odata[-4];
		size_t ia_response_len = 0;
		// Default to handing out the whole delegated block when the
		// client doesn't send an explicit size hint, instead of always
		// carving out a fixed /62 -- e.g. with a /56 delegation and a
		// single downstream router, that router should just get the
		// /56 as-is.
		uint8_t reqlen = (is_pd) ? ((iface->pd_addr_len > 0) ? iface->pd_addr[0].prefix : 62) : 128;
		uint32_t reqhint = 0;

		// Parse request hint for IA-PD
		if (is_pd) {
			uint8_t *sdata;
			uint16_t stype, slen;
			dhcpv6_for_each_option(&ia[1], odata + olen, stype, slen, sdata) {
				if (stype == DHCPV6_OPT_IA_PREFIX && slen >= sizeof(struct dhcpv6_ia_prefix) - 4) {
					struct dhcpv6_ia_prefix *p = (struct dhcpv6_ia_prefix *)&sdata[-4];
					if (p->prefix) {
						reqlen = p->prefix;
						reqhint = ntohl(p->addr.s6_addr32[1]);
						if (reqlen > 32 && reqlen <= 64)
							reqhint &= (1U << (64 - reqlen)) - 1;
					}
					break;
				}
			}

			if (reqlen > 64)
				reqlen = 64;
		}

		// Find assignment
		struct assignment *c, *a = NULL;
		list_for_each_entry(c, &iface->pd_assignments, head) {
			if (c->clid_len == clid_len && !memcmp(c->clid_data, clid_data, clid_len) && (c->iaid == ia->iaid || c->valid_until < now) &&
				((is_pd && c->length <= 64) || (is_na && c->length == 128))) {
				a = c;

				// Reset state
				apply_lease(iface, a, false);
				a->iaid = ia->iaid;
				a->peer = *addr;
				a->reconf_cnt = 0;
				a->reconf_sent = 0;
				break;
			}
		}

		// Generic message handling
		uint16_t status = DHCPV6_STATUS_OK;
		if (hdr->msg_type == DHCPV6_MSG_SOLICIT || hdr->msg_type == DHCPV6_MSG_REQUEST) {
			bool assigned = !!a;

			if (!a) { // Create new binding
				a = calloc(1, sizeof(*a) + clid_len);
				a->clid_len = clid_len;
				a->iaid = ia->iaid;
				a->length = reqlen;
				a->peer = *addr;
				a->assigned = reqhint;
				if (first)
					memcpy(a->key, first->key, sizeof(a->key));
				else
					relayd_urandom(a->key, sizeof(a->key));
				memcpy(a->clid_data, clid_data, clid_len);

				if (is_pd)
					while (!(assigned = assign_pd(iface, a)) && ++a->length <= 64)
						;
				else
					assigned = assign_na(iface, a);
			}

			if (!assigned || iface->pd_addr_len == 0) { // Set error status
				status = (is_pd) ? DHCPV6_STATUS_NOPREFIXAVAIL : DHCPV6_STATUS_NOADDRSAVAIL;
			} else if (assigned && !first) { //
				size_t handshake_len = 4;
				buf[0] = 0;
				buf[1] = DHCPV6_OPT_RECONF_ACCEPT;
				buf[2] = 0;
				buf[3] = 0;

				if (hdr->msg_type == DHCPV6_MSG_REQUEST) {
					struct dhcpv6_auth_reconfigure auth = {
						htons(DHCPV6_OPT_AUTH), htons(sizeof(auth) - 4), 3, 1, 0, {htonl(time(NULL)), htonl(++serial)}, 1, {0}};
					memcpy(auth.key, a->key, sizeof(a->key));
					memcpy(buf + handshake_len, &auth, sizeof(auth));
					handshake_len += sizeof(auth);
				}

				buf += handshake_len;
				buflen -= handshake_len;
				response_len += handshake_len;

				first = a;
			}

			ia_response_len = append_reply(buf, buflen, status, ia, a, iface, true);

			// Was only a solicitation: mark binding for removal
			if (assigned && hdr->msg_type == DHCPV6_MSG_SOLICIT) {
				a->valid_until = 0;
			} else if (assigned && hdr->msg_type == DHCPV6_MSG_REQUEST) {
				if (hostname_len > 0) {
					a->hostname = realloc(a->hostname, hostname_len + 1);
					memcpy(a->hostname, hostname, hostname_len);
					a->hostname[hostname_len] = 0;
				}
				a->accept_reconf = accept_reconf;
				apply_lease(iface, a, true);
				update_state = true;
			} else if (!assigned && a) { // Cleanup failed assignment
				free(a->hostname);
				free(a);
			}
		} else if (hdr->msg_type == DHCPV6_MSG_RENEW || hdr->msg_type == DHCPV6_MSG_RELEASE || hdr->msg_type == DHCPV6_MSG_REBIND ||
				   hdr->msg_type == DHCPV6_MSG_DECLINE) {
			if (!a && hdr->msg_type != DHCPV6_MSG_REBIND) {
				status = DHCPV6_STATUS_NOBINDING;
				ia_response_len = append_reply(buf, buflen, status, ia, a, iface, false);
			} else if (hdr->msg_type == DHCPV6_MSG_RENEW || hdr->msg_type == DHCPV6_MSG_REBIND) {
				// If we currently have nothing usable to hand back (e.g.
				// the delegated prefix just changed and pd-lease-watcher
				// hasn't applied the new one yet), explicitly invalidate
				// the client's current binding (valid=0/preferred=0)
				// instead of either staying silent or replying with a
				// bare NoPrefixAvail/NoAddrsAvail status. Both of those
				// were tried first and neither actually got MikroTik's
				// dhcpv6-client to drop the old routes: silence just
				// looks like packet loss (client keeps the binding and
				// retries per its own Renew/Rebind timers), and a status
				// code with no address/prefix option isn't the same as
				// being told THIS SPECIFIC prefix is now dead. A Reply
				// that echoes the client's own prefix/address back with
				// valid=0 is unambiguous and is what tears it down
				// immediately.
				bool usable = false;
				if (a) {
					for (size_t i = 0; i < iface->pd_addr_len; ++i) {
						if (iface->pd_addr[i].prefix <= 64 && iface->pd_addr[i].preferred > (uint32_t)now) {
							usable = true;
							break;
						}
					}
				}

				if (a && !usable) {
					ia_response_len = append_invalidate_reply(buf, buflen, ia, a, iface);
					apply_lease(iface, a, false);
				} else {
					ia_response_len = append_reply(buf, buflen, status, ia, a, iface, false);
					if (a)
						apply_lease(iface, a, true);
				}
			} else if (hdr->msg_type == DHCPV6_MSG_RELEASE) {
				a->valid_until = 0;
				apply_lease(iface, a, false);
				update_state = true;
			} else if (hdr->msg_type == DHCPV6_MSG_DECLINE && a->length == 128) {
				a->clid_len = 0;
				a->valid_until = now + 3600; // Block address for 1h
				update_state = true;
			}
		} else if (hdr->msg_type == DHCPV6_MSG_CONFIRM) {
			// Always send NOTONLINK for CONFIRM so that clients restart connection
			status = DHCPV6_STATUS_NOTONLINK;
			ia_response_len = append_reply(buf, buflen, status, ia, a, iface, true);
		}

		buf += ia_response_len;
		buflen -= ia_response_len;
		response_len += ia_response_len;
	}

	if (hdr->msg_type == DHCPV6_MSG_RELEASE && response_len + 6 < buflen) {
		buf[0] = 0;
		buf[1] = DHCPV6_OPT_STATUS;
		buf[2] = 0;
		buf[3] = 2;
		buf[4] = 0;
		buf[5] = DHCPV6_STATUS_OK;
		response_len += 6;
	}

	if (update_state) {
		write_statefile();
		write_keyfile();
	}

out:
	return response_len;
}
