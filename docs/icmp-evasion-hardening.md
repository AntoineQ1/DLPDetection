# ICMP Detection — Review, Hardening & Evaluation Findings

Author: Sofia

Peer review of the ICMP covert-channel mechanism, mirroring the review
Antoine did on the DNS work. Scope: `detection/covert_channel/icmp_detector.py`,
its sniffer wiring, `attacks/icmp_exfiltrate.py`, `servers/icmp_sink.py`, and
`docs/icmp-detection-mecanism.md`. Every finding below was verified against
the live detector. The mechanism is solid for the closed lab and the four
demo scenarios; this review is about where it breaks outside that happy path.


---

## A. Detection gaps — things it *can't see* (false negatives)

### A1 — It only reads "question" pings, never "answer" pings

> **In plain words:** The detector inspects Echo *Requests* and completely
> ignores Echo *Replies*. It's like a guard who searches everyone walking
> **into** the building but never searches anyone walking **out** — so you
> just carry the loot out the door. Smuggling data in reply pings is the
> normal way ICMP tunnels work, and the detector sees none of it.
>
> *Proof:* the exact credit card that gets caught in a request packet
> produces **zero alerts** when sent in a reply packet.

Technically: `parse_icmp_echo` returns `None` for any `icmp.type != 8`, so
Echo Reply (0), Timestamp (13/14), Information (15/16), and data smuggled in
the quoted packet of ICMP error messages (3/11) are all dropped before any
rule runs. Real ICMP tunnels (ptunnel, Loki, icmptunnel) exfiltrate over
replies. This is **the biggest gap**. Tracked as issue #9 (open).

### A2 — A trusted "timestamp" slot the attacker can fill with secrets

> **In plain words:** A normal Linux ping's bag = `[16 bytes of timestamp] +
> [a fixed counting pattern]`. The detector only checked that the *counting
> pattern* part was correct, and then trusted the whole ping — it never
> looked at the first 16 bytes at all. So the attacker could write 16 bytes
> of secret where the timestamp goes, keep the normal pattern after it, and
> the ping sailed through as "just a normal Linux ping." 16 bytes per ping:
> slow, but totally invisible.
>
> *Proof:* 16 arbitrary bytes + the Linux pattern = whitelisted as benign →
> **zero alerts**.

Technically: `is_known_benign_payload` accepted any 56-byte payload whose
bytes `[16:]` equaled the fixed Linux pattern; bytes `[0:16]` (the real
kernel `timeval` slot) were never validated. **Fixed** — tracked as issue
#11 (closed), commit `ea2ac4c`: validates the 16-byte timeval prefix and
routes the identifier/sequence bytes through the content scanner. See the
evaluation-correction section below for the real cost of this fix.



---

## B. False positives — normal traffic it *wrongly flags*

### B1 — Any big ping is screamed at as an attack

> **In plain words:** The detector yells "ATTACK!" (HIGH severity) at *any*
> ping bigger than 64 bytes — even when there's nothing bad inside. But
> network admins send big pings all the time to test the network (MTU/path
> testing).
>
> *Proof:* a harmless 108-byte ping (`ping -s 100`) → one HIGH
> `icmp_oversized_payload` alert, nothing sensitive present.

Technically: the oversized rule triggers on `payload_size > 64` with no
content or rate gate. No issue filed as this is a design decision.



### B2 — "More than 4 pings a second" is treated as suspicious

> **In plain words:** The detector flags any computer sending more than 4
> pings per second. But lots of normal tools do way more than that: 
> network scanners, monitoring dashboards, fast diagnostic pings.

Technically: `DEFAULT_MAX_REQUESTS_PER_WINDOW = 4` per 1 s. Flood ping,
`ping -i 0.2`, `fping`/`nmap -sn` sweeps, and smokeping all exceed it. No
issue filed, this is a design decision.

---

## C. Robustness — ways to break or dodge the detector

### C1 — It never forgets a computer, so you can exhaust its memory

> **In plain words:** To do the speed check, the detector keeps a little
> notebook entry for every computer it has ever seen pinging, and never
> erases old ones. Flood it with pings pretending to come from millions of
> different computers and the notebook grows forever until the detector
> runs out of memory and falls over.
>
> *Proof:* after 1000 distinct source IPs, all 1000 entries are still kept
> (in a real flood that's millions, unbounded).

Technically: `ICMPRateTracker._history` is a `defaultdict` with no eviction
— unlike the DNS detector, which has `_periodic_cleanup`. Tracked as issue
#13 (open), already fixed independently (see below).

### C2 — A fake return address slips past the speed check

> **In plain words:** The speed check counts pings *per sender*. But a
> sender can lie about who it is. If every ping claims to come from a
> different computer, each one looks like "just 1 ping," so the speed alarm
> never goes off.
>
> *Proof:* 1000 packets, each from a different spoofed source → the rate
> rule never fires once.

Technically: rate state is keyed on source IP, which the passive sniffer
never validates, so source spoofing defeats the only behavioral rule (and
feeds C1). No issue filed, accepted limitation of passive IP-keyed rate
limiting.

### Minor
- Structural rules are mutually exclusive (first match returns), so an
  oversized packet is only labeled "oversized" and loses the finer signal.
- `decode("utf-8", errors="ignore")` silently drops non-UTF8 bytes (low
  risk — it concatenates, so cards survive).

---

## Issues opened from this review

- **[#9 — Echo Reply (type 0) outbound exfiltration is not inspected](https://github.com/AntoineQ1/DLPDetection/issues/9)
  (open).** A1 above. No fix identified.
- **[#11 — A "benign" Linux ping carries ~20 uninspected bytes/packet](https://github.com/AntoineQ1/DLPDetection/issues/11)
  (closed).** A2 above. Fixed by commit `ea2ac4c`. The eval-fixture bug
  documented below was discovered while checking this fix's reported
  false-positive cost — the real cost is ~zero, not the 65% originally
  measured.
- **[#13 — Rate tracker never evicts source IPs, unbounded memory growth](https://github.com/AntoineQ1/DLPDetection/issues/13)
  (open).** C1 above. Already fixed independently by Antoine (commit
  `5e36702` on `origin/evaluation/icmp-memory-exhaustion`, bounded
  `OrderedDict` with LRU eviction), but that branch has no open PR and isn't
  merged into `main` or `dns-icmp-eval` yet — issue filed to track and link
  it so the fix doesn't get lost.



---

## Evaluation finding: stale benign-Linux-ping fixture inflated A2's reported cost

While checking A2/#11's fix for false-positive cost, the 65% benign
false-positive rate the offline evaluation reported for ICMP turned out to
be mostly a bug in the evaluation's own benign-traffic generator, not a real
cost of that fix.


### Fix

`evaluation/run_covert_eval.py`, `icmp_benign_packets`: use a real
`time.time()` split into `tv_sec`/`tv_usec` for the `linux_default_ping`
fixture, matching what an actual Linux ping sends.

```python
now = time.time()
tv_sec = int(now)
tv_usec = int((now - tv_sec) * 1_000_000)
payload = (
    tv_sec.to_bytes(8, "little", signed=True)
    + tv_usec.to_bytes(8, "little", signed=True)
    + LINUX_PING_PATTERN
)
```




