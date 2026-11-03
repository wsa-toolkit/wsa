# WSA — Wireless Security Assessment Framework

> tmux-based wireless assessment conductor for OPEN, WEP, WPA-Personal,
> WPA3, and WPA-Enterprise networks. NIST SP 800-53 remediation reports
> with a teaching-grade methodology reference for each protocol.

WSA is a single-file Python assessment engine that drives aircrack-ng,
hostapd-mana, hashcat, and john from a unified terminal UI. It is
designed for two audiences:

- **Students** — methodology text, references, and a teaching-grade
  walkthrough for each wireless protocol, so you learn *why* each step
  exists, not just what command to type.
- **Practitioners** — structured capture, filter, and recovery pipeline
  that produces a plain-text assessment report with NIST SP 800-53
  control mappings, ready to hand to a reviewer.

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

## Why WSA (and not wifite, airgeddon, or fluxion)

Kali already ships three mature wireless assessment orchestrators:
wifite2, airgeddon, and fluxion. WSA is not a replacement for any of
them. It occupies a different niche:

- **Curriculum-first.** Every protocol has a teaching-grade reference
  with peer-reviewed citations (Borisov WEP 2001, Vanhoef KRACK 2017,
  Vanhoef Dragonblood 2020, RFC 3748/5216/5281, NIST SP 800-53),
  prerequisites, assessment criteria, and step-by-step diagrams.
  Wifite has none of this. Airgeddon is a bash script. Fluxion is a
  captive portal tool.

- **Reportable.** Every assessment folder produces a plain-text report
  with NIST SP 800-53 remediation controls mapped to the finding. That
  is what a compliance reviewer signs off on. WSA was built around
  that deliverable, not around the attack itself.

- **Material purity.** The analysis console filters rogue-side
  handshakes (those that crack with the fake rogue PSK) out of
  subsequent mask attacks, so 45-minute recovery runs only test
  material that can produce a real target recovery. This is invisible
  in wifite/airgeddon because they don't distinguish rogue-side from
  real-side captures.

- **Single-file.** 6,000 lines, no dependencies beyond stdlib, no
  build step. `sudo python3 wsa.py` and it runs. Portable, auditable,
  hackable.

WSA is complementary to the existing tools. It is not a wifite clone.

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

`john` is optional — only used in the enterprise analysis console
alternative recovery path.

## Hardware

WSA runs on any Kali-compatible wireless adapter. Two physical radios
add one attack capability — single radio covers the rest.

### One adapter (standard laptop, VM, or single dongle)

- **WEP assessment** — capture, fake auth, ARP replay, key recovery
- **WPA / WPA2 personal** — evil twin, handshake capture, PSK recovery
- **WPA3 personal** — transition-mode downgrade, handshake recovery
- **WPA / WPA2 / WPA3 enterprise** — rogue AP, EAP credential harvest

One radio performs each phase sequentially. No mode conflict because
WEP and the evil-twin family use only one mode at a time per flow.

### Two adapters (professional bench)

Everything above, plus:

- **OPEN network assessment** — capture clients on one radio, spoof,
  associate, and verify access on the second

OPEN flow requires monitor mode (capture, deauth) and managed mode
(MAC spoof, association, connectivity test) running simultaneously.
Two radios eliminate the mode-switch race.

### Recommended adapters

- Atheros AR9271  (TP-Link TL-WN722N v1, Alfa AWUS036NHA)
- MediaTek MT7612U (Alfa AWUS036ACM)
- Ralink RT3070   (Alfa AWUS036NH)

All three pass through VirtualBox cleanly and support monitor +
injection + AP modes.

## Quick Start

```bash
git clone https://github.com/wsa-toolkit/wsa.git
cd wsa
sudo python3 wsa.py
