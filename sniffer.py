import socket
import struct
import os
import sys
import time
import threading

try:
    from colorama import init, Fore, Style
except ImportError:
    class Dummy:
        def __getattr__(self, name): return ''
    init = lambda: None
    Fore = Style = Dummy()

init(autoreset=True)

LANGS = {
    "tr": {
        "welcome": "🛡️ Canlı Ağ Trafiği İzleyici",
        "choose_lang": "Dil seçin (tr/en): ",
        "root_warn": "❗ Lütfen scripti sudo ile çalıştırın!",
        "exit": "Çıkılıyor, iyi günler!",
        "ethernet": "💾 Ethernet Çerçevesi",
        "ipv4": "🌐 IPv4 Paketi",
        "tcp": "🔵 TCP",
        "udp": "🟣 UDP",
        "icmp": "🔷 ICMP",
        "proto": "Protokol",
        "from": "Kaynak",
        "to": "Hedef"
    },
    "en": {
        "welcome": "🛡️ Live Network Traffic Sniffer",
        "choose_lang": "Select language (tr/en): ",
        "root_warn": "❗ Please run script with sudo!",
        "exit": "Exiting, goodbye!",
        "ethernet": "💾 Ethernet Frame",
        "ipv4": "🌐 IPv4 Packet",
        "tcp": "🔵 TCP",
        "udp": "🟣 UDP",
        "icmp": "🔷 ICMP",
        "proto": "Protocol",
        "from": "From",
        "to": "To"
    }
}

ASCII_BANNER = [
    Fore.CYAN + "   _____  .__                              ________           ________                       .___",
    Fore.CYAN + "  /  _  \\ |  |__  _  _______  ___.__. _____\\_____  \\   ____  /  _____/ __ _______ _______  __| _/",
    Fore.BLUE + " /  /_\\  \\|  |\\ \\/ \\/ /\\__  \\<   |  |/  ___//   |   \\ /    \\/   \\  ___|  |  \\__  \\\\_  __ \\/ __ | ",
    Fore.BLUE + "/    |    \\  |_\\     /  / __ \\\\___  |\\___ \\/    |    \\   |  \\    \\_\\  \\  |  // __ \\|  | \\/ /_/ | ",
    Fore.MAGENTA + "\\____|__  /____/\\/\\_/  (____  / ____/____  >_______  /___|  /\\______  /____/(____  /__|  \\____ | ",
    Fore.MAGENTA + "        \\/                  \\/\\/         \\/        \\/     \\/        \\/           \\/           \\/ ",
    Fore.YELLOW + Style.BRIGHT + "                                                        Network Sniffer Tool / By 01fromoon"
]

def get_lang():
    lang = input(LANGS['en']['choose_lang'])
    return 'tr' if lang.lower() == 'tr' else 'en'

def animate_banner():
    os.system("cls" if os.name == "nt" else "clear")
    for line in ASCII_BANNER:
        print(line)
        time.sleep(0.07)
    print(Fore.YELLOW + "═" * 80)
    time.sleep(0.2)

def spinner(stop_event, lang):
    spin_chars = ["|", "/", "-", "\\"]
    idx = 0
    while not stop_event.is_set():
        print(Fore.YELLOW + f"\r   {spin_chars[idx % len(spin_chars)]} {LANGS[lang]['welcome']}", end='', flush=True)
        idx += 1
        time.sleep(0.1)
    print("\r" + " " * 60, end='\r')  # Clear line

def main():
    lang = get_lang()
    animate_banner()
    L = LANGS[lang]
    if os.name != "nt":
        if os.geteuid() != 0:
            print(Fore.RED + L["root_warn"])
            sys.exit(1)
    else:
        print(Fore.RED + L["root_warn"])
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except Exception as e:
        print(Fore.RED + f"Socket error: {e}")
        sys.exit(1)
    stop_event = threading.Event()
    spinner_thread = threading.Thread(target=spinner, args=(stop_event, lang))
    spinner_thread.start()
    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            stop_event.set()
            spinner_thread.join()
            print(Fore.YELLOW + "\n" + "═" * 80)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print(
                Fore.YELLOW
                + f"{L['ethernet']}: {src_mac} {Fore.BLUE}→{Fore.YELLOW} {dest_mac} {Fore.CYAN}({L['proto']}: {eth_proto})"
            )
            if eth_proto == 8:
                (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
                print(
                    Fore.CYAN
                    + f"{L['ipv4']}: {src} {Fore.BLUE}→{Fore.CYAN} {target} {Fore.MAGENTA}({L['proto']}: {proto}, TTL:{ttl})"
                )
                if proto == 6:
                    src_port, dest_port, *_ = tcp_segment(data)
                    print(
                        Fore.GREEN
                        + f"{L['tcp']}: {src}:{src_port} {Fore.BLUE}→{Fore.GREEN} {target}:{dest_port}"
                    )
                elif proto == 17:
                    src_port, dest_port, *_ = udp_segment(data)
                    print(
                        Fore.MAGENTA
                        + f"{L['udp']}: {src}:{src_port} {Fore.BLUE}→{Fore.MAGENTA} {target}:{dest_port}"
                    )
                elif proto == 1:
                    icmp_type, code, *_ = icmp_packet(data)
                    print(
                        Fore.BLUE
                        + f"{L['icmp']}: Type {icmp_type}, Code {code}"
                    )
            print(Fore.YELLOW + "═" * 80)
            stop_event.clear()
            spinner_thread = threading.Thread(target=spinner, args=(stop_event, lang))
            spinner_thread.start()
            time.sleep(0.07)
    except KeyboardInterrupt:
        stop_event.set()
        spinner_thread.join()
        print(Fore.YELLOW + "\n" + L["exit"])
        sys.exit(0)

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
    return (
        get_mac_addr(dest_mac),
        get_mac_addr(src_mac),
        socket.htons(proto),
        data[14:],
    )

def get_mac_addr(bytes_addr):
    return ":".join(map("{:02x}".format, bytes_addr)).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return ".".join(map(str, addr))

def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack(
        "! H H L L H", data[:14]
    )
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgement, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    return src_port, dest_port, size, data[8:]

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]

if __name__ == "__main__":
    main()
