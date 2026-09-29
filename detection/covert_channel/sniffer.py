import os
import time

from scapy.all import DNS, ICMP, IP, conf, get_if_addr, get_if_list, sniff

from detection.covert_channel.dns_analyzer import analyze_dns_packet

# Lab subnet that the victim lives on. Sniffing the interface that carries this
# subnet lets us observe exfiltration at its source (and avoids double-counting
# the same packet again after the gateway forwards it out the external side).
INTERNAL_SUBNET_PREFIX = os.environ.get("INTERNAL_SUBNET_PREFIX", "172.20.0.")
BPF_FILTER = "icmp or udp port 53"


def analyze_packet(pkt) -> None:
    if not pkt.haslayer(IP):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    print(f"[DEBUG-SNIFFER] Packet intercepted : {src_ip} -> {dst_ip}", flush=True)

    if pkt.haslayer(ICMP):
        pass  # TODO: icmp_analyzer, blocked on attacks/icmp_exfiltrate.py
    elif pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        analyze_dns_packet(pkt)


def pick_interfaces() -> list[str]:
    """Return capture interfaces, preferring the internal (victim) subnet.

    Falls back to every non-loopback interface that currently has an IPv4
    address, so the sniffer still works if the lab addressing changes.
    """
    internal, usable = [], []
    for iface in get_if_list():
        if iface == "lo":
            continue
        try:
            addr = get_if_addr(iface)
        except Exception:
            continue
        if not addr or addr == "0.0.0.0":
            continue  # interface not up / no IPv4 yet
        usable.append(iface)
        if addr.startswith(INTERNAL_SUBNET_PREFIX):
            internal.append(iface)
    return internal or usable


def main() -> None:
    print("[DLP-COVERT] Passive sniffer starting...", flush=True)

    # Wait for the shared netns interfaces to come up (avoids the startup race
    # where scapy opens a socket on an interface that is still 'Network is down').
    ifaces: list[str] = []
    for _ in range(30):
        ifaces = pick_interfaces()
        if ifaces:
            break
        time.sleep(1)

    if not ifaces:
        print("[DLP-COVERT] No usable interface found; sniffing default.", flush=True)
        ifaces = [conf.iface]

    print(f"[DLP-COVERT] Listening on {ifaces} (filter: {BPF_FILTER})", flush=True)

    # Retry loop: a transient interface flap should not kill the detector.
    while True:
        try:
            sniff(
                iface=ifaces,
                filter=BPF_FILTER,
                prn=analyze_packet,
                store=False,
            )
        except OSError as exc:
            print(f"[DLP-COVERT] capture socket error ({exc}); retrying in 2s", flush=True)
            time.sleep(2)
            ifaces = pick_interfaces() or ifaces



if __name__ == "__main__":
    main()
