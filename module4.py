import subprocess
from scapy.all import IP, TCP, send
from netfilterqueue import NetfilterQueue

# 1. Kernel-Level Blacklisting via ipset
def init_firewall():
    subprocess.run(["sudo", "ipset", "create", "blacklist", "hash:ip", "timeout", "3600", "-exist"])
    subprocess.run(["sudo", "iptables", "-I", "INPUT", "-m", "set", "--match-set", "blacklist", "src", "-j", "DROP"])
    print("[+] Firewall & IP blacklist hash set ready.")

def blacklist_ip(ip_address, timeout=3600):
    cmd = ["sudo", "ipset", "add", "blacklist", ip_address, "timeout", str(timeout), "-exist"]
    subprocess.run(cmd)
    print(f"[!] Banned IP: {ip_address} for {timeout} seconds.")

# 2. Active Teardown: Inject forged TCP RST packets
def kill_tcp_connection(attacker_ip, target_ip, attacker_port, target_port):
    rst_to_attacker = IP(src=target_ip, dst=attacker_ip) / TCP(sport=target_port, dport=attacker_port, flags="R")
    rst_to_target = IP(src=attacker_ip, dst=target_ip) / TCP(sport=attacker_port, dport=target_port, flags="R")
    send(rst_to_attacker, verbose=False)
    send(rst_to_target, verbose=False)
    print(f"[!] Sent forged TCP RST between {attacker_ip}:{attacker_port} and {target_ip}:{target_port}.")

# 3. Inline Dropping via NetfilterQueue
def packet_inspector(packet):
    # Retrieve raw packet bytes
    # Modules 2 and 3 flag malicious traffic here
    is_malicious = True

    if is_malicious:
        print("[!] Dropping malicious packet inline!")
        packet.drop()
    else:
        packet.accept()

def start_inline_filter(queue_num=0):
    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_num, packet_inspector)
    print(f"[*] Intercepting packets on NFQUEUE {queue_num} (Press Ctrl+C to stop)...")
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\nStopping queue listener...")
        nfqueue.unbind()

# Runner Block
if __name__ == "__main__":
    init_firewall()
    print("Module 4 (Active Prevention & Dynamic Enforcement) is ready!")
    start_inline_filter(queue_num=0)