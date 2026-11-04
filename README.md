# WSA — Wireless Security Assessment Framework

> A tmux-based conductor for wireless security assessments across OPEN,
> WEP, WPA-Personal, WPA3, and WPA-Enterprise networks. NIST SP 800-53
> control mappings in every report, with a methodology reference for
> each protocol built into the tool.

WSA drives aircrack-ng, hostapd-mana, hashcat, and john from a single
terminal UI. It runs each assessment as a structured procedure, records
what it does, and produces a plain-text report mapping the finding to
NIST SP 800-53 remediation controls.

## The doorway model

Every wireless network is a door. The protocol tells you what kind of
lock is on it — and therefore what an assessment looks like:

- **Some are open** — nothing asked, nothing returned.  *(OPEN / OWE)*
- **Some are open at the radio** — the ask arrives later, on a web
  page.  *(captive portal)*
- **Some ask for a key** — the lock was broken decades ago.  *(WEP)*
- **Some ask for a passphrase** — one shared secret, negotiated.
  *(WPA / WPA2 / WPA3 personal)*
- **Some ask for a name** — a username, a password, per person.
  *(WPA2 / WPA3 enterprise)*
- **Some ask for proof** — a certificate, one side or both.  *(EAP-TLS)*

Knowing which door you are facing tells you which procedure to run,
what to capture, what to expect at each step, and how to defend against
it. Every procedure in WSA follows the same shape — **understand the
door, find the weakness, produce the report**.

## What WSA is not

WSA does not replace expertise. It makes expertise reproducible.

Every command is shown alongside its rationale. Every capture is
classified before it is cracked — rogue-side material is filtered out
of subsequent mask and wordlist attacks, so a 45-minute recovery only
tests what could yield a real target recovery. Every assessment ends
with a report a reviewer can sign off on.

If you already know the protocol, WSA keeps the assessment consistent
and reportable. If you are learning it, the same procedure shows you
why each step exists — not just what to type.

## Relationship to existing tools

Kali ships wifite2, airgeddon, and fluxion — three mature wireless
assessment orchestrators. WSA is not a replacement for any of them. It
is complementary, and takes a different shape:

- **Methodology is a first-class output.** Each protocol has a
  built-in reference with primary-source citations (Borisov WEP 2001,
  Vanhoef KRACK 2017, Vanhoef Dragonblood 2020, RFC 3748/5216/5281,
  NIST SP 800-53) and step-by-step diagrams. The reference renders in
  the same terminal as the procedure.

- **Every assessment produces a report.** Plain-text, with NIST
  SP 800-53 remediation controls mapped to the finding — a deliverable
  for a compliance reviewer, not a session log.

- **Material purity.** Rogue-side handshakes — those that crack with
  the fake rogue PSK — are filtered out of subsequent recovery runs,
  so long mask and wordlist attacks only test material that can
  produce a real target recovery. Distinguishing rogue-side from
  real-side captures is built into the analysis stage.

- **Single-file engine.** ~6,000 lines, Python stdlib only, no pip
  installs, no build step. `sudo python3 wsa.py` and it runs.
  Portable, auditable, forkable.

## Legal Notice

WSA is intended for **authorized security assessments only**.

Use of this tool against networks you do not own, or have not been given
explicit written authorization to test, is illegal in most jurisdictions.
The authors assume no liability for misuse.

Before using WSA:

- Obtain written authorization from the network owner
- Document the scope (ESSIDs, BSSIDs, time windows)
- Comply with all applicable laws (CFAA in the US, Computer Misuse Act
  in the UK, similar statutes worldwide)
- Prefer isolated lab environments for training and experimentation

WSA is designed for:

- Authorized penetration testing engagements
- Security training in controlled lab environments
- Internal wireless security audits on networks you own

WSA is not designed for:

- Unauthorized access to wireless networks
- "War driving" or "wardialing"
- Any activity that violates local or international law

## Requirements

WSA must be run as root:

    sudo python3 wsa.py

Wireless operations require `CAP_NET_ADMIN` and raw socket access.
The tool will not function without root privileges.

### Required packages

On Kali Linux:

    sudo apt install -y aircrack-ng hashcat iw network-manager tmux
    # hostapd-mana is not in apt — build from source:
    git clone https://github.com/sensepost/hostapd-mana.git
    cd hostapd-mana && sudo make install

`john` is optional — used only in the enterprise analysis console
alternative recovery path.

## Hardware

Development was done on Alfa AWUS036H, AWUS036ACH, and AWUS036AXML —
capable, but not necessary. In practice, a single TP-Link Archer T2U
Nano (Realtek RTL8811AU, USB ID `2357:011e`) covers every flow
described below, and a pair of them covers OPEN as well. What matters
is monitor mode, packet injection, and AP mode support; most
Kali-compatible adapters provide all three. Expensive hardware is not
a prerequisite.

### One adapter

Covers every flow except OPEN:

- **WEP** — capture, fake auth, ARP replay, key recovery
- **WPA / WPA2 personal** — evil twin, handshake capture, PSK recovery.
  The evil-twin flow does not send intentional deauthentication. It
  mirrors the target ESSID and BSSID and relies on clients that probe
  for the SSID; channel-hopping increases the chance of interception
  without disrupting the network.
- **WPA3 personal** — transition-mode downgrade, handshake recovery
- **WPA / WPA2 / WPA3 enterprise** — rogue AP, EAP credential harvest

One adapter performs each phase sequentially. WEP and the evil-twin
family use a single mode at a time per flow, so a second radio is not
required.

### Two adapters

Everything above, plus OPEN, where monitor mode (capture, deauth) and
managed mode (spoof, association, verification) must run
simultaneously. The OPEN flow uses deauth to keep a single stable
handshake — one MAC associated at a time, not two racing the same AP.
Two radios eliminate the mode-switch race.

## Quick Start

    git clone https://github.com/wsa-toolkit/wsa.git
    cd wsa
    sudo python3 wsa.py
