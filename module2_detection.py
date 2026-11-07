import time
import re
from collections import defaultdict, deque

class DetectionEngine:
    def __init__(self, port_scan_threshold=10, window_seconds=5.0, syn_ratio_threshold=3.0):
        self.port_scan_threshold = port_scan_threshold
        self.window_seconds = window_seconds
        self.syn_ratio_threshold = syn_ratio_threshold

        # Sliding window state storage: src_ip -> deque of (timestamp, dst_port)
        self.port_scan_tracker = defaultdict(deque)

        # SYN Flood tracking: src_ip -> deque of (timestamp, flag_type)
        self.syn_tracker = defaultdict(deque)

        # Signatures for SQLi and XSS
        self.sqli_patterns = [
            re.compile(r"('|\%27)\s*(or|and)\s*.*?(=|<|>)", re.IGNORECASE),
            re.compile(r"union\s+select", re.IGNORECASE),
            re.compile(r"'\s*or\s*1\s*=\s*1", re.IGNORECASE)
        ]
        self.xss_patterns = [
            re.compile(r"<script.*?>", re.IGNORECASE),
            re.compile(r"onerror\s*=", re.IGNORECASE),
            re.compile(r"onload\s*=", re.IGNORECASE)
        ]

    def _clean_window(self, tracker_deque, current_time):
        """Removes entries older than window_seconds."""
        while tracker_deque and (current_time - tracker_deque[0][0]) > self.window_seconds:
            tracker_deque.popleft()

    def check_port_scan(self, src_ip, dst_port, current_time):
        """Detects > N distinct ports queried within T seconds."""
        records = self.port_scan_tracker[src_ip]
        records.append((current_time, dst_port))
        self._clean_window(records, current_time)

        distinct_ports = {port for _, port in records}
        if len(distinct_ports) > self.port_scan_threshold:
            return True, f"Horizontal Port Scan detected: {len(distinct_ports)} ports scanned in {self.window_seconds}s"
        return False, ""

    def check_syn_flood(self, src_ip, is_syn, is_ack, current_time):
        """Detects abnormal SYN to ACK/SYN-ACK ratio."""
        records = self.syn_tracker[src_ip]
        if is_syn and not is_ack:
            records.append((current_time, "SYN"))
        elif is_ack:
            records.append((current_time, "ACK"))

        self._clean_window(records, current_time)

        syn_count = sum(1 for _, kind in records if kind == "SYN")
        ack_count = sum(1 for _, kind in records if kind == "ACK")

        if syn_count > 15 and (ack_count == 0 or (syn_count / (ack_count + 1)) > self.syn_ratio_threshold):
            return True, f"SYN Flood detected: {syn_count} SYNs vs {ack_count} ACKs"
        return False, ""

    def check_signatures(self, normalized_payload):
        """Inspects normalized HTTP/application text for SQLi and XSS."""
        if not normalized_payload:
            return False, ""

        for pattern in self.sqli_patterns:
            if pattern.search(normalized_payload):
                return True, "SQL Injection signature matched!"

        for pattern in self.xss_patterns:
            if pattern.search(normalized_payload):
                return True, "XSS signature matched!"

        return False, ""