# ARP Guardian System (AGS)

Link explanation video (YouTube): https://youtu.be/lq2bAzYJtmk?si=sQCawkKL5vHGTYp4

## What It Does

AGS is a Flask + Scapy ARP spoof detector. It:
- builds a baseline IP->MAC map of your LAN,
- sniffs ARP traffic in real time,
- flags IP/MAC mismatches as spoofing events,
- exposes events and topology through a web UI.

## Quick Start (Linux)

1. Create and activate virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements
```

3. Run with root privileges (required for packet sniffing/raw ARP):

```bash
sudo .venv/bin/python -m src.app
```

4. Open UI:

```text
http://127.0.0.1:5000
```

## Runtime Network Configuration

The detector now auto-detects:
- active interface from default route,
- subnet CIDR from interface address,
- gateway IP from route table.

Optional overrides:

```bash
export AGS_IFACE=wlan0
export AGS_SUBNET=192.168.1.0/24
sudo .venv/bin/python -m src.app
```

Check runtime configuration:

```bash
curl http://127.0.0.1:5000/api/config
```

## Real LAN Testing (Attacker + Victim)

1. Start AGS on detector machine.
2. Click Start Monitoring in UI.
3. From attacker machine, run ARP spoof toward victim and gateway (example):

```bash
sudo arpspoof -i <attacker_iface> -t <victim_ip> <gateway_ip>
sudo arpspoof -i <attacker_iface> -t <gateway_ip> <victim_ip>
```

4. Open the events page in AGS and verify detected entries.

## Important Limitation in Switched LANs

As described in the project report, passive out-of-line detection cannot always see unicast ARP replies between other hosts on switched networks.

To detect spoofing across the whole LAN (not only attacks involving the detector host), use one of:
- SPAN/mirror port on a managed switch,
- detector positioned inline,
- detector as default gateway with forwarding enabled.

## Detector as Default Gateway (Effective Mode)

If you choose gateway mode on the detector host:

1. Enable IP forwarding:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

2. Allow forwarding/NAT (adapt interface names):

```bash
sudo iptables -P FORWARD ACCEPT
sudo iptables -t nat -A POSTROUTING -o <uplink_iface> -j MASQUERADE
```

3. Set LAN clients' default gateway to detector IP.

This gives AGS visibility of ARP traffic for all clients and makes spoof detection significantly more reliable.
