import time
from netfilterqueue import NetfilterQueue
import module1_parser as parser
from module2_detection import DetectionEngine
import module4

# Initialize detection and enforcement
detector = DetectionEngine(port_scan_threshold=5, window_seconds=3.0)
module4.init_firewall()

def packet_callback(packet):
    raw_bytes = packet.get_payload()
    current_time = time.time()

    # --- Module 1: Zero-Copy Parsing ---
    ip_info = parser.parse_ipv4_header(raw_bytes)
    if not ip_info:
        packet.accept()
        return

    src_ip = ip_info["src_ip"]
    is_malicious = False
    alert_reason = ""

    # Protocol 6 = TCP
    if ip_info["protocol"] == 6:
        tcp_info = parser.parse_tcp_header(ip_info["payload"])
        if tcp_info:
            # --- Module 2: Stateful Heuristics ---
            is_scan, scan_msg = detector.check_port_scan(src_ip, tcp_info["dst_port"], current_time)
            if is_scan:
                is_malicious = True
                alert_reason = scan_msg

            is_syn_flood, flood_msg = detector.check_syn_flood(src_ip, tcp_info["syn"], tcp_info["ack_flag"], current_time)
            if is_syn_flood:
                is_malicious = True
                alert_reason = flood_msg

            # --- Module 1: Normalization & Module 2: Signature Detection ---
            normalized_text = parser.normalize_payload(tcp_info["payload"])
            is_exploit, exploit_msg = detector.check_signatures(normalized_text)
            if is_exploit:
                is_malicious = True
                alert_reason = exploit_msg

    # --- Module 4: Dynamic Enforcement ---
    if is_malicious:
        print(f"\n[ALERT] {alert_reason} from {src_ip}")
        print(f"[ACTION] Dropping packet and blacklisting IP {src_ip} via ipset!")
        module4.blacklist_ip(src_ip, timeout=600)
        packet.drop()
    else:
        packet.accept()

def run_ids():
    nfqueue = NetfilterQueue()
    # Queue num 1 as specified in Module 1 requirements
    nfqueue.bind(1, packet_callback)
    print("[*] Complete IDS/IPS running on NFQUEUE 1. Listening for traffic...")
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\nStopping IDS/IPS...")
        nfqueue.unbind()

if __name__ == "__main__":
    run_ids()