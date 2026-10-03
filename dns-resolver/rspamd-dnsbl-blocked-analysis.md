# Rspamd DNS lists are partly and intermittently blocked on YunoHost: queries go through shared public resolvers

**Component:** Rspamd DNS lookups (RBL/URIBL/DNSWL/rDNS) on a YunoHost mail server
**Affected:** every YunoHost server that keeps the default `dnsmasq` setup, not only this fork
**Status:** Analysed and verified on the production server, including a per-upstream test of
each list. Option A is implemented in the rspamd_ynh fork (4.2.1~ynh5) and deployed on
2026-10-03; all three lists answer correctly through the local resolver (see "Result after
deploying option A"). The DNSWL per-upstream result needs a recheck, see below.

---

## Summary

Rspamd sends its DNS queries to `127.0.0.1` (YunoHost's `dnsmasq`). `dnsmasq` forwards them
to a hard-coded pool of 13 public resolver addresses, run mostly by non-profit ISPs. A
per-upstream test of each list's test entries showed that the lists behave differently:

- **URIBL** is blocked through all 13 upstreams. It is effectively unusable in this setup.
- **DNSWL** was counted as blocked through all 13 upstreams, but that count treated
  `127.0.10.0` as "blocked". According to dnswl.org, `127.0.10.0` is the normal answer for
  the test entry, so upstreams that returned it actually worked. Only `127.0.0.255` means
  blocked. Which upstreams really block DNSWL needs a recheck.
- **Spamhaus (ZEN and DBL)** works through 10 of the 13 upstreams. It is blocked only
  through DNS4all (`194.0.5.3`, `2001:678:8::3`). Which upstream answers depends on
  `dnsmasq`'s choice, so Spamhaus fails intermittently.
- **One upstream is dead.** `194.150.168.168` (AS250) times out.

The checks are not dead, though. In the log there are still real hits: `DBL_SPAM` 268×,
`DBL_PHISH` 30×, `RECEIVED_SPAMHAUS_*` about 1900×, `URIBL_BLACK` 6×,
`RCVD_IN_DNSWL_MED` 242× and `DWL_DNSWL_MED` 245×. But the share of blocked lookups is
large and growing:

- Over six months, 7801 of 15 060 messages (52 %) had at least one blocked DBL, URIBL or
  DNSWL lookup.
- In September, of 3246 incoming messages, 898 had a blocked DBL lookup, 458 a blocked
  URIBL lookup and 1025 a blocked DNSWL lookup.

Effects:

- **Spam indicators are lost part of the time.** The Spamhaus DBL scores 5.0–7.5 per hit,
  `URIBL_BLACK` 7.5.
- **Whitelisting of good senders is often lost.** DNSWL gives up to −0.5, DWL up to −3.5.
- **Occasional reverse-DNS failures add false spam points to legitimate mail.**
  `RDNS_NONE` (2.0) plus `HFILTER_HOSTNAME_UNKNOWN` (2.5) add 4.5 points. This is a minor
  issue: 74 cases in six months, and the likely cause is upstream timeouts, not blocking.

The fix recommended by Rspamd itself is a local recursive resolver (Unbound) that only
Rspamd uses. It removes the dependency on the upstream pool for all lists at once.

## Environment

- YunoHost on Debian 13 (Trixie), `resolvconf` installed, `unbound` not installed
- Rspamd 4.2.1 (rspamd_ynh fork, 4.2.1~ynh4), thresholds `add_header = 4`, `reject = 12`
- Default YunoHost DNS setup: `/etc/resolv.conf` → `127.0.0.1` (`dnsmasq`) → 13 upstreams
  in `/etc/resolv.dnsmasq.conf`
- No `/etc/rspamd/local.d/options.inc`, so Rspamd uses `/etc/resolv.conf` (→ `dnsmasq`)

## Evidence

### Symbol counts

Symbol occurrences in `/var/log/rspamd/rspamd.log` (2026-04-04 to 2026-10-02):

```
sudo grep -oE '[A-Z_]*BLOCKED[A-Z_]*|RDNS_DNSFAIL' /var/log/rspamd/rspamd.log | sort | uniq -c
```

| Symbol | Count | Meaning |
|---|---:|---|
| `DBL_BLOCKED_OPENRESOLVER` | 4298 | Spamhaus DBL answered `127.255.255.254` ("query via public/open resolver") |
| `DNSWL_BLOCKED` | 3277 | dnswl.org answered with a code Rspamd treats as blocked (`127.0.0.255` or `127.0.10.x`) |
| `DWL_DNSWL_BLOCKED` | 1329 | Same for the DKIM-domain whitelist (dwl.dnswl.org) |
| `URIBL_BLOCKED` | 1222 | URIBL answered `127.0.0.1` ("query refused") |
| `RDNS_DNSFAIL` | 74 | Reverse-DNS (PTR) lookup of the sending IP failed |

`BLOCKED_CLIENT_IP`, `BLOCKED_ENVFROM_DOMAIN`, `BLOCKED_HELO_HOSTNAME` and
`BLOCKED_SENDER_DOMAIN` also match this grep pattern. They are this fork's local multimap
blocklists and are unrelated.

The counts are symbol occurrences, not messages. One message can trigger
`DBL_BLOCKED_OPENRESOLVER` several times, once per domain in it. 430 of the DBL blocks come
from outgoing authenticated mail (`settings_id: outbound_authenticated`). That mail is not
scored, so these blocks don't matter.

### Messages affected

One `rspamd_task_write_log` line per scanned message:

| Period | Messages | With ≥1 blocked DBL / URIBL / DNSWL lookup |
|---|---:|---:|
| 2026-04-04 – 2026-10-02 | 15 060 | 7801 (52 %) |

The share of blocked lookups is growing. September 2026, incoming mail only:

| Incoming messages | DBL blocked | URIBL blocked | DNSWL blocked |
|---:|---:|---:|---:|
| 3246 | 898 (28 %) | 458 (14 %) | 1025 (32 %) |

### Real hits still get through

| Symbol | Count |
|---|---:|
| `DBL_SPAM` | 268 |
| `DBL_PHISH` | 30 |
| `RECEIVED_SPAMHAUS_*` | ~1900 |
| `URIBL_BLACK` | 6 |
| `RCVD_IN_DNSWL_MED` | 242 |
| `DWL_DNSWL_MED` | 245 |

For Spamhaus this matches the per-upstream test below: most upstreams work. URIBL is
blocked through all current upstreams, so its few hits probably came through upstreams in
the pool order of earlier months. The pool is reshuffled monthly; see Root cause. This is
not verified. The DNSWL hits fit the corrected reading of the per-upstream test: some
upstreams probably do get answers from dnswl.org.

### Per-upstream test

Each list's documented test entry was queried directly against each of the 13 upstreams in
`/etc/resolv.dnsmasq.conf` (command under "Verification commands"):

| List | Result across the 13 upstreams |
|---|---|
| Spamhaus ZEN and DBL | Works through 10 of 13. Blocked (`127.255.255.254`) only through DNS4all, `194.0.5.3` and `2001:678:8::3` |
| URIBL | Blocked through all (`127.0.0.1`) |
| DNSWL | Recheck needed. `127.0.0.255` = blocked; `127.0.10.0` = the documented answer for the test entry, so the query worked |
| — | `194.150.168.168` (AS250) times out: the server is dead |

### rDNS failures

All 74 messages with `RDNS_DNSFAIL` also got `RDNS_NONE` (2.0), and 73 of them
`HFILTER_HOSTNAME_UNKNOWN` (2.5). So a failed PTR lookup is treated like "no rDNS" and adds
up to 4.5 points. That alone reaches the `add_header` threshold of 4.

A failing PTR lookup is not a blocklist effect. The likely cause is timeouts, for example
through the dead upstream `194.150.168.168`. With 74 cases in six months this is a minor
issue.

### Example: legitimate mailing-list mail scored as spam

A GitHub notification delivered through the `vger.kernel.org` mailing list. This is an
excerpt; the full line also lists 0-point symbols, among them `RDNS_DNSFAIL` and
`DNSWL_BLOCKED`:

```
(add header): [9.04/12.00] [R_DKIM_REJECT(3.00), HFILTER_HOSTNAME_UNKNOWN(2.50), RDNS_NONE(2.00),
 DMARC_POLICY_QUARANTINE(1.50), ARC_ALLOW(-1.00), FROM_NEQ_ENVFROM(1.00), ...,
 DNSWL_BLOCKED(0.00){...}, RDNS_DNSFAIL(0.00){}, ...]
```

The PTR lookup failed (`RDNS_DNSFAIL`), so Rspamd treated the sender as having no rDNS and
added 4.5 points. Whether the sending host actually has valid reverse DNS was not checked.
DNSWL, which might have given a negative score to the kernel.org relay, was blocked as well.

## Root cause

### 1. YunoHost forwards all DNS to a fixed pool of public resolvers

YunoHost's `dnsmasq` regen-conf hook (`hooks/conf_regen/43-dnsmasq`) writes
`/etc/resolv.dnsmasq.conf` from `conf/dnsmasq/plain/resolv.dnsmasq.conf`. That file lists
13 public resolver addresses run by ARN, Aquilenet, AS250, Ideal-Hosting and DNS4all.

- **Monthly reshuffle:** the hook reshuffles the list once a month, seeded from the machine
  ID and the month. So the pool order, and with it the upstream that `dnsmasq` prefers,
  changes over time.
- **Custom resolvers:** these can be set in the YunoHost settings
  (`dns_custom_resolvers_*`).

`dnsmasq` does not stick to one upstream. It prefers servers that answer and re-evaluates
them, so successive Rspamd lookups can go through different upstreams.

### 2. The list operators treat these upstreams differently

- **URIBL** answers `127.0.0.1` (refused) to blocked resolvers and when the free quota is
  exceeded. Through all 13 upstreams the test entry is refused. Rspamd maps this to
  `URIBL_BLOCKED`.
- **dnswl.org** answers `127.0.0.255` to blocked or over-quota resolvers (more than
  100 000 queries a day, which shared resolvers easily reach). Rspamd maps this to
  `DNSWL_BLOCKED` and `DWL_DNSWL_BLOCKED`. Rspamd also maps `127.0.10.x` there, although
  category 10 is "some special cases" at dnswl.org, and `127.0.10.0` is the documented
  answer for the test entry `127.0.0.2`. So `DNSWL_BLOCKED` in the log slightly overcounts
  real blocks, and a test answer of `127.0.10.0` means the query worked.
- **Spamhaus** (ZEN, DBL) answers `127.255.255.254` to queries from public or open
  resolvers. Rspamd maps this to `*_BLOCKED_OPENRESOLVER`. In the test only DNS4all is
  blocked. The other upstreams get real answers.

So for URIBL the problem is the shared pool as a whole. For Spamhaus it is the
mix of working and blocked upstreams: the result depends on which upstream `dnsmasq`
happens to use.

All `*_BLOCKED` symbols score 0.0. They only signal that the list could not be used.

### 3. One upstream is dead

`194.150.168.168` (AS250) does not answer. While `dnsmasq` still tries it, lookups can time
out. This is the most likely cause of the `RDNS_DNSFAIL` cases.

### 4. Rspamd explicitly warns about this

From the Rspamd FAQ, "Resolver setup":

> if you rely on your service provider's resolver or a public resolver, you could encounter
> issues such as being blocked by the majority of DNS list providers

The FAQ recommends running your own recursive resolver (Unbound or Knot Resolver).

## Impact

Default scores (Rspamd 4.2.1) of the checks that are lost whenever a lookup is blocked:

| Check | Symbols | Score | Availability today |
|---|---|---|---|
| Spamhaus DBL (domains in URLs/headers) | `DBL_SPAM` / `DBL_PHISH` / `DBL_MALWARE` / `DBL_ABUSE*` | 6.5 / 7.5 / 7.5 / 5.0–6.5 | Intermittent (blocked for 28 % of incoming mail in September) |
| URIBL | `URIBL_BLACK` / `URIBL_GREY` / `URIBL_RED` | 7.5 / 2.5 / 0.5 | Practically none |
| DNSWL (sending IP) | `RCVD_IN_DNSWL_LOW` / `_MED` / `_HI` | −0.1 / −0.2 / −0.5 | Intermittent (blocked for 32 % of incoming mail in September) |
| DNSWL DWL (DKIM domain) | `DWL_DNSWL_LOW` / `_MED` / `_HI` | −1.0 / −2.0 / −3.5 | Intermittent |
| rDNS failure (false positive) | `RDNS_NONE` + `HFILTER_HOSTNAME_UNKNOWN` | +2.0 / +2.5 | 74 cases in six months |

Both effects push in the wrong direction: spam scores lower than it should, and legitimate
mail loses its whitelist bonus. With the fork's aggressive threshold (`add_header = 4`
instead of the default 6), a failed rDNS lookup alone is enough to move a legitimate message
into Junk, but that happens rarely.

## Open questions

1. **Spamhaus ZEN never shows blocked hits.** `RBL_SPAMHAUS_BLOCKED_OPENRESOLVER` and
   `RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER` never appear, although ZEN uses the same
   upstreams as DBL and DNS4all blocks both in the test.
   - **One lead:** 430 of the DBL blocks come from outgoing authenticated mail. There DBL
     checks domains from rDNS and mail addresses, while ZEN apparently checks nothing.
   - **Still open:** that doesn't explain why incoming mail never gets a ZEN block.
2. **Time span of the counts.** Answered: 2026-04-04 to 2026-10-02, see Evidence.
3. **Messages affected.** Answered: 7801 of 15 060 messages, with a rising share. See
   Evidence.

## Verification commands

Resolver chain:

```bash
cat /etc/resolv.conf
cat /etc/resolv.dnsmasq.conf
```

Time span and number of affected messages (one `rspamd_task_write_log` line per message):

```bash
sudo head -1 /var/log/rspamd/rspamd.log | cut -c1-19; sudo tail -1 /var/log/rspamd/rspamd.log | cut -c1-19
sudo grep -c rspamd_task_write_log /var/log/rspamd/rspamd.log
sudo grep rspamd_task_write_log /var/log/rspamd/rspamd.log | grep -cE 'DBL_BLOCKED_OPENRESOLVER|URIBL_BLOCKED|DNSWL_BLOCKED'
```

Test entries of each list, through the current resolver chain. These are the operators'
documented test entries:

```bash
dig +short 2.0.0.127.zen.spamhaus.org          # listed: 127.0.0.2/.4/.10   blocked: 127.255.255.254
dig +short dbltest.com.dbl.spamhaus.org        # listed: 127.0.1.2          blocked: 127.255.255.254
dig +short test.uribl.com.multi.uribl.com      # listed: 127.0.0.14         blocked: 127.0.0.1
dig +short 2.0.0.127.list.dnswl.org            # blocked: 127.0.0.255 (any other 127.0.x.y means the query got through)
```

The same test against each upstream separately:

```bash
for ns in $(awk '/^nameserver/ {print $2}' /etc/resolv.dnsmasq.conf); do echo "$ns: $(dig +short +time=2 +tries=1 @"$ns" dbltest.com.dbl.spamhaus.org | tr '\n' ' ')"; done
```

The same queries against a local recursive resolver (after option A below) should return
the "listed" answers:

```bash
dig +short -p 5353 @127.0.0.1 dbltest.com.dbl.spamhaus.org
```

## Options

### A. Local Unbound for Rspamd only (recommended)

Unbound runs as a recursive resolver on a non-standard port, so it does not collide with
`dnsmasq` on port 53. Only Rspamd is pointed at it. YunoHost's system DNS stays unchanged.

```
# /etc/unbound/unbound.conf.d/rspamd.conf
server:
    interface: 127.0.0.1@5353
    access-control: 127.0.0.0/8 allow
    prefetch: yes
```

```
# /etc/rspamd/local.d/options.inc
dns {
  nameserver = ["127.0.0.1:5353"];
}
```

- **Pros:**
  - Fixes URIBL and DNSWL completely.
  - Removes the Spamhaus dropouts through DNS4all.
  - Removes the timeouts caused by the dead upstream.
  - Follows Rspamd's own recommendation and leaves YunoHost's DNS setup alone.
- **Cons:** one more service to run. Free DNS list quotas now apply per server IP, which
  is fine at this volume (about 3000 incoming messages a month).
- **Watch out:** `resolvconf` is installed on this server. On Debian, the `unbound` package
  ships `unbound-resolvconf.service`, which then may point `/etc/resolv.conf` at Unbound and
  conflict with YunoHost's `dnsmasq`. Disable it:
  `systemctl disable --now unbound-resolvconf`.

**Integration into the rspamd_ynh fork:**

- **manifest:** add `unbound` to the apt resources.
- **install / upgrade:** deploy the two files above, then restart `unbound` and `rspamd`.
- **remove:** delete both files. Remove or stop `unbound` only if nothing else uses it.
- **backup / restore:** include both files.
- **Service check:** register `unbound` as a YunoHost service, so that `yunohost service`
  shows its state.
- **Check after deploy:** the `dig -p 5353` tests above, and new `*_BLOCKED*` counts
  dropping to zero in the Rspamd log.

### B. Change YunoHost's system resolvers

Set custom resolvers in the YunoHost settings. This affects the whole system.

- **Prune the pool:** dropping DNS4all and the dead `194.150.168.168` would likely fix the
  Spamhaus dropouts and the timeouts. URIBL stays blocked, though: it refuses all
  13 upstreams.
- **Use a provider resolver:** a hoster's resolver is often blocked by the list operators
  for the same reason.

Not recommended as the main fix. Pruning the pool is a possible short-term mitigation for
Spamhaus.

### C. Spamhaus DQS (Data Query Service)

Spamhaus offers a free key-based service for low-volume users. Queries go to a per-key
zone and work through any resolver. This covers only Spamhaus (ZEN, DBL). URIBL, DNSWL and
the rDNS failures stay unfixed. It also needs a registration and extra Rspamd
configuration. Possible as an addition to option A, not as a replacement.

### D. Do nothing

URIBL stays unusable, DNSWL and Spamhaus keep failing intermittently, and the share of
blocked lookups keeps growing. Occasional rDNS timeouts keep producing false positives
under the fork's aggressive thresholds.

## Recommendation

Implement option A inside the rspamd_ynh fork, so the setup is reproducible and covered by
backup and restore. Done; see the next section.

Over the next days, check:

- **Blocked symbols:** new `DBL_BLOCKED_OPENRESOLVER` and `URIBL_BLOCKED` counts should
  drop to zero. `DNSWL_BLOCKED` should become rare. It can't drop to exactly zero, because
  Rspamd also files category-10 listings (`127.0.10.x`) under it.
- **List hits:** `URIBL_*` and `RCVD_IN_DNSWL_*` hits should rise noticeably.
- **Spamhaus ZEN:** whether ZEN behaves differently, which may help answer open question 1.

## Result after deploying option A

Deployed on 2026-10-03 as rspamd_ynh fork 4.2.1~ynh5 (`yunohost app upgrade`).

**Upgrade log:** one expected warning, `Could not execute systemctl: at
/usr/bin/deb-systemd-invoke line 148`. The `unbound` package starts the service right
after installation on port 53, where `dnsmasq` already listens. The package tolerates the
failed start, and the upgrade script then restarts Unbound on port 5353.

**Test entries through the local resolver:**

```
$ dig +short -p 5353 @127.0.0.1 dbltest.com.dbl.spamhaus.org     -> 127.0.1.2   (listed, works)
$ dig +short -p 5353 @127.0.0.1 test.uribl.com.multi.uribl.com   -> 127.0.0.14  (listed, works)
$ dig +short -p 5353 @127.0.0.1 2.0.0.127.list.dnswl.org         -> 127.0.10.0  (documented test answer, works)
```

**System state:**

- `unbound`, `rspamd` and `dnsmasq` are all `active`.
- `/etc/resolv.conf` still points to `127.0.0.1` (`dnsmasq`). The system DNS is unchanged.
- `/etc/rspamd/local.d/options.inc` points Rspamd to `127.0.0.1:5353`.

## References

- Rspamd FAQ, "Resolver setup": <https://rspamd.com/doc/faq.html>
- Rspamd DNS options (`local.d/options.inc`): <https://rspamd.com/doc/configuration/options.html>
- Spamhaus DNSBL usage FAQ (public/open resolvers): <https://www.spamhaus.org/faq/section/DNSBL%20Usage>
- URIBL refused queries: <https://uribl.com/refused.shtml>
- YunoHost dnsmasq resolver list: `conf/dnsmasq/plain/resolv.dnsmasq.conf` and
  `hooks/conf_regen/43-dnsmasq` in <https://github.com/YunoHost/yunohost>
- Rspamd 4.2.1 return codes: `conf/modules.d/rbl.conf`. Scores: `conf/scores.d/rbl_group.conf`
  and `surbl_group.conf`.
