import sys

from scapy.all import DNS, ICMP, IP, sniff


def analyze_packet(pkt) -> None:
    if not pkt.haslayer(IP):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    print(f"[DEBUG-SNIFFER] Packet intercepted : {src_ip} -> {dst_ip}", flush=True)

    if pkt.haslayer(ICMP):
        pass
    elif pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        pass


if __name__ == "__main__":
    print("[DLP-COVERT] Passive sniffer listening on gateway interfaces...")
    sys.stdout.flush()
    sniff(filter="icmp or udp port 53", prn=analyze_packet, store=False)
