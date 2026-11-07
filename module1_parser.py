import struct
import socket
import urllib.parse

def parse_ipv4_header(raw_data):
    """
    Parses IPv4 Header using struct.unpack (Zero-Copy / Low overhead)
    Standard IPv4 header size: 20 bytes (minimum)
    """
    if len(raw_data) < 20:
        return None
    
    # '!BBHHHBBH4s4s' formats 20 bytes into standard IP header fields
    ip_header = struct.unpack('!BBHHHBBH4s4s', raw_data[:20])
    version_ihl = ip_header[0]
    ihl = (version_ihl & 0xF) * 4 # Header length in bytes
    protocol = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])

    return {
        "ihl": ihl,
        "protocol": protocol, # 6 = TCP, 17 = UDP, 1 = ICMP
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "payload": raw_data[ihl:]
    }

def parse_tcp_header(raw_data):
    """
    Parses TCP Header using struct.unpack
    Standard TCP header size: 20 bytes (minimum)
    """
    if len(raw_data) < 20:
        return None
    
    # '!HHIIBBHHH' formats the first 20 bytes of TCP header
    tcp_header = struct.unpack('!HHIIBBHHH', raw_data[:20])
    src_port = tcp_header[0]
    dst_port = tcp_header[1]
    seq = tcp_header[2]
    ack = tcp_header[3]
    offset_reserved = tcp_header[4]
    tcp_offset = (offset_reserved >> 4) * 4 # Offset in bytes
    flags = tcp_header[5]

    # TCP Flag decoding
    flag_syn = bool(flags & 0x02)
    flag_ack = bool(flags & 0x10)
    flag_rst = bool(flags & 0x04)
    flag_fin = bool(flags & 0x01)

    payload = raw_data[tcp_offset:]

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "syn": flag_syn,
        "ack_flag": flag_ack,
        "rst": flag_rst,
        "fin": flag_fin,
        "payload": payload
    }

def normalize_payload(raw_bytes):
    """
    Decodes raw application layer bytes, handles URL decoding (%20, %27),
    and converts to canonical lower-case string for signature inspection.
    """
    if not raw_bytes:
        return ""
    
    # Decode to text ignoring unprintable characters
    decoded_text = raw_bytes.decode('utf-8', errors='ignore')
    
    # URL decode (%27 -> ', %20 -> space)
    normalized = urllib.parse.unquote(decoded_text)
    
    return normalized