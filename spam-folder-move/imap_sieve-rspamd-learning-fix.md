# Dovecot 2.4 imap_sieve: Rspamd Bayes learning does not trigger when a mail client moves a message to/from Junk via IMAP APPEND

**Component:** Dovecot anti-spam / imap_sieve integration (Rspamd learn on drag-to-Junk)
**Config file affected:** `/etc/dovecot/yunohost.d/post-ext.d/antispam.conf`
**Status:** Reproduced and fixed in production. See proposed change below.

---

## Summary

The shipped `antispam.conf` configures the imap_sieve learning hooks with
`cause = copy` only. Several common IMAP clients (notably **Microsoft Outlook**)
do **not** move a message into the Junk folder with an IMAP `COPY`; instead they
**`APPEND`** the message to the target folder and `EXPUNGE` the original.
Because the sieve hooks only listen for `copy`, the learning script is **never
invoked** for those clients, so Rspamd Bayes is never trained from manual
Junk/not-Junk moves.

The fix is to listen for both causes: `cause = copy append`.

A second, related issue: the referenced sieve scripts are loaded by absolute
`path` and are **not pre-compiled**. The IMAP process cannot write the compiled
`.svbin` next to the script (directory not writable for it), which can lead to a
silent no-op. Shipping pre-compiled `.svbin` files (or making compilation
succeed) makes the hooks reliable.

## Environment

- YunoHost on Debian 13
- Dovecot **2.4.1-4**
- Rspamd (Bayes + Redis, autolearn enabled) — all working
- Affected client: **Outlook over IMAP**. Thunderbird / Roundcube / scripts that
  use IMAP `COPY` were unaffected, which is exactly why the bug looked
  intermittent ("sometimes it learns, sometimes it doesn't").

## Symptom

- Moving a message Inbox → Junk (or Junk → Inbox) from Outlook produces only
  `COPY`/`APPEND` + `EXPUNGE` in `/var/log/mail.log`, but **no** `sieve:` action
  and **no** `learned message as spam/ham` in `/var/log/rspamd/rspamd.log`.
- The same move from a client/tool that uses IMAP `COPY` *does* trigger learning.

## Root cause

`antispam.conf` registers the imap_sieve scripts with `cause = copy`:

```
mailbox Junk {
  sieve_script report-spam-junk {
    type = before
    cause = copy
    path = /usr/lib/dovecot/sieve/report-spam.sieve
  }
}
imapsieve_from Junk {
  sieve_script report-ham-junk {
    type = before
    cause = copy
    path = /usr/lib/dovecot/sieve/report-ham.sieve
  }
}
```

Outlook implements "move to Junk" as **`APPEND` to Junk + `EXPUNGE` from Inbox**,
not as `COPY`. With `cause = copy`, imap_sieve ignores the `APPEND` event, so the
`report-spam` / `report-ham` scripts (and therefore `rspamc learn_spam/learn_ham`)
never run.

## Fix

### 1. Listen for both `copy` and `append`

Change `cause = copy` to `cause = copy append` in all four sieve_script blocks
(`mailbox Spam`, `imapsieve_from Spam`, `mailbox Junk`, `imapsieve_from Junk`),
then restart Dovecot. See `antispam.conf.diff` in this folder.

```
-    cause = copy
+    cause = copy append
```

```bash
doveconf -n >/dev/null && systemctl restart dovecot
```

### 2. Pre-compile the sieve scripts

The scripts are loaded by absolute `path`; the IMAP process could not write the
compiled binary back into `/usr/lib/dovecot/sieve`, which caused a silent
failure when no `.svbin` was present. Pre-compiling makes loading deterministic:

```bash
sievec /usr/lib/dovecot/sieve/report-spam.sieve
sievec /usr/lib/dovecot/sieve/report-ham.sieve
# -> creates report-spam.svbin / report-ham.svbin
```

## Verification (real Outlook move to Junk, with `log_debug = category=sieve`)

```
Mailbox Junk: imapsieve: APPEND event
Mailbox Junk: imapsieve: storage report-spam-junk: Using Sieve script path: .../report-spam.sieve
sieve: action pipe: running program: rspamd-learn-spam.sh
APPEND "Junk" () ... <811 byte literal>: OK [APPENDUID ... 44]
```

`/var/log/rspamd/rspamd.log` then shows `learned message as spam` for that move.

## Suggested upstream change

Ship the imap_sieve hooks with `cause = copy append` instead of `cause = copy`,
so that learning works for clients (Outlook and others) that move messages via
`APPEND`. Additionally, ship the sieve scripts pre-compiled (`.svbin`) or ensure
the script directory allows compilation, to avoid the silent-no-op failure mode.

## Diagnostic pitfalls (cost us time — documented for others)

- **`PrivateTmp=yes`** on the Dovecot systemd unit: a trace written to `/tmp` by
  the pipe script is invisible from a root shell (Dovecot has its own `/tmp`).
  Do not interpret an empty trace file as "the script didn't run".
- **`autolearn = true`**: incoming mail is often already learned, so a manual
  `learn_spam` may not increment the counter. `rspamc stat` "Messages learned"
  is therefore not a reliable success signal — the Dovecot `log_debug` output is.
- **Username form:** Outlook may authenticate as the short local part
  (`genealogie`) while a script test uses the full address
  (`genealogie@fluid8.de`). Use a wildcard when filtering debug:
  `log_debug = user="genealogie*"`.
- **Testing:** `doveadm copy/move/save` bypasses imap_sieve hooks entirely; only
  a real IMAP session triggers learning. Test from an actual client.

## References

- Dovecot 2.4 imap_sieve plugin: <https://doc.dovecot.org/latest/core/plugins/imap_sieve.html>
- Dovecot 2.4 Sieve troubleshooting: <https://doc.dovecot.org/2.4.4/core/config/sieve/troubleshooting.html>
- howtoforge thread (same scenario): <https://forum.howtoforge.com/threads/issue-with-rspamd-learning-imapsieve-on-dovecot-2-4-1-debian-13.95068/>
