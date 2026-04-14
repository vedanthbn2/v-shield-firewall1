from scapy.all import sniff, IP, TCP
from collections import defaultdict
import os
import time
import threading
from colorama import init, Fore

init(autoreset=True)

# ================= CONFIG =================
INTERFACE = "eth0"   # change if needed (ip a)
THRESHOLD = 40
BLOCK_TIME = 10
# =========================================

packet_count = defaultdict(int)
blocked_ips = set()
start_time = time.time()

# ============== BANNER ====================
def banner():
    os.system("clear")

    print(Fore.RED + """
██╗   ██╗    ███████╗    ███████╗ ██╗  ██╗███████╗██╗     ██████╗ 
██║   ██║    ██╔════╝    ██╔════╝ ██║  ██║██╔════╝██║     ██╔══██╗
██║   ██║    ███████╗    ███████╗ ███████║█████╗  ██║     ██║  ██║
╚██╗ ██╔╝    ╚════██║    ╚════██║ ██╔══██║██╔══╝  ██║     ██║  ██║
 ╚████╔╝     ███████║    ███████║ ██║  ██║███████╗███████╗██████╔╝
  ╚═══╝      ╚══════╝    ╚══════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝ 
""")

    print(Fore.YELLOW + "===================================================")
    print(Fore.YELLOW + "        V-SHIELD IDS / IPS FIREWALL SYSTEM")
    print(Fore.YELLOW + "===================================================")

    print(Fore.CYAN + "  Owner   : vedanth shetty")
    print(Fore.CYAN + "  Engine  : Scapy Packet Analyzer")
    print(Fore.CYAN + "  Mode    : Real-Time Intrusion Detection")
    print(Fore.CYAN + "  Version : 1.0.0 LAB EDITION")

    print(Fore.GREEN + "===================================================")
    print(Fore.MAGENTA + "              SYSTEM INITIALIZING...")
    print(Fore.GREEN + "===================================================\n")


def loading():
    print(Fore.YELLOW + "Starting V-SHIELD Engine", end="")
    for _ in range(5):
        time.sleep(0.3)
        print(".", end="")
    print("\n")


# ============== AUTO UNBLOCK =============
def auto_unblock(ip):
    time.sleep(BLOCK_TIME)
    os.system(f"iptables -D INPUT -s {ip} -j DROP")
    print(Fore.GREEN + f"[UNBLOCKED] {ip}")
    blocked_ips.discard(ip)


# ============== PACKET HANDLER ============
def packet_callback(packet):

    global start_time

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    packet_count[src_ip] += 1

    now = time.time()
    interval = now - start_time

    if interval >= 1:
        for ip, count in packet_count.items():
            rate = count / interval

            if rate > THRESHOLD and ip not in blocked_ips:
                print(Fore.RED + f"[ALERT] Attack detected from {ip} | rate={rate:.1f}")
                print(Fore.YELLOW + f"[ACTION] Blocking {ip}")

                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                blocked_ips.add(ip)

                threading.Thread(
                    target=auto_unblock,
                    args=(ip,),
                    daemon=True
                ).start()

        packet_count.clear()
        start_time = now


# ============== MAIN ======================
if __name__ == "__main__":

    banner()
    loading()

    if os.geteuid() != 0:
        print("Run as root!")
        exit()

    print(Fore.GREEN + "[+] Monitoring traffic...\n")

    sniff(iface=INTERFACE, prn=packet_callback, store=0)