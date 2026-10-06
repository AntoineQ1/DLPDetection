from scapy.layers.inet import ICMP, IP
from scapy.packet import Packet
from scapy.sendrecv import sniff

from ui.display import (
    print_hint,
    print_status,
    print_success,
    render_debug_flow,
    render_payload_telemetry,
)


def handle_packet(pkt: Packet) -> None:
    # Filter for IP/ICMP Echo Request (type 8)
    if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)):
        return

    icmp_layer = pkt[ICMP]
    if icmp_layer.type != 8:
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    payload = bytes(icmp_layer.payload)
    seq = getattr(icmp_layer, "seq", None)

    render_debug_flow("ICMP", src_ip, dst_ip)
    panel_title = f"Intercepted ICMP Echo [Seq={seq} from {src_ip}]"
    render_payload_telemetry(payload, panel_title=panel_title)
    print_success(f"Extracted {len(payload)} bytes from {src_ip}")


def main():
    print_status("Starting ICMP listener...")
    print_hint("Sniffing Echo Requests (filter: 'icmp')...")

    try:
        sniff(filter="icmp", prn=handle_packet, store=False)
    except KeyboardInterrupt:
        print_status("Stopping listener...")


if __name__ == "__main__":
    main()
