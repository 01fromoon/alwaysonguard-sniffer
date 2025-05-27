# 🛡️ Network Sniffer Tool

## 🚀 Quick Start (English)
A terminal-based, colorful, live network sniffer with ASCII banner and multi-language (English/Turkish) support.  
Monitors your network traffic in real-time on **Linux** using Python and displays protocol, source/destination IP, and port with emojis and color!

---

### 📥 Installation

```bash
# 1️⃣ Clone the repository
git clone https://github.com/01fromoon/alwaysonguard-sniffer.git
cd alwaysonguard-sniffer

# 2️⃣ Install required Python packages
pip install colorama

# 3️⃣ Run the sniffer with root privileges (Linux only)
sudo python3 sniffer.py
```

---

### ⚡ Usage

- Choose your language (**en** or **tr**) when prompted.
- Watch the live, colorful, emoji-enhanced traffic in your terminal!
- Press **CTRL+C** to exit.

---

### ❗ Requirements

- Linux operating system
- Python 3.x
- Root privileges (use `sudo`)
- `colorama` Python package

---

### 🛑 Notes

- **Does NOT work on Windows!** (`socket.AF_PACKET` is not available on Windows)
- For educational and analysis purposes only.
- Supports live capture and real-time colorized display of Ethernet, IPv4, TCP, UDP, and ICMP packets.

---

## 📝 Example Output

```text
   _____  .__                              ________           ________                       .___
  /  _  \ |  |__  _  _______  ___.__. _____\_____  \   ____  /  _____/ __ _______ _______  __| _/
 /  /_\  \|  |\ \/ \/ /\__  \<   |  |/  ___//   |   \ /    \/   \  ___|  |  \__  \\_  __ \/ __ | 
/    |    \  |_\     /  / __ \\___  |\___ \/    |    \   |  \    \_\  \  |  // __ \|  | \/ /_/ | 
\____|__  /____/\/\_/  (____  / ____/____  >_______  /___|  /\______  /____/(____  /__|  \____ | 
        \/                  \/\/         \/        \/     \/        \/           \/           \/ 
                                                        Network Sniffer Tool / By 01fromoon

💾 Ethernet Frame: 4A:5B:6C:7D:8E:9F → 00:11:22:33:44:55 (Protocol: 8)
🌐 IPv4 Packet: 192.168.1.5 → 142.250.186.206 (Protocol: 6, TTL: 64)
🔵 TCP: 192.168.1.5:56544 → 142.250.186.206:443
```

---

## 🇹🇷 Hızlı Başlangıç (Türkçe)
Terminalde çalışan, renkli ASCII başlıklı, canlı ağ trafiği izleme aracı.  
Python ile yazılmıştır ve **Linux** üzerinde gerçek zamanlı olarak ağ paketlerini renkli ve emojili şekilde gösterir!

---

### 📥 Kurulum

```bash
# 1️⃣ Depoyu klonla
git clone https://github.com/01fromoon/alwaysonguard-sniffer.git
cd alwaysonguard-sniffer

# 2️⃣ Gerekli Python paketini kur
pip install colorama

# 3️⃣ Aracı root (sudo) ile başlat (sadece Linux)
sudo python3 sniffer.py
```

---

### ⚡ Kullanım

- Başlangıçta **en** veya **tr** dilini seçin.
- Terminalde canlı, renkli ve emojili paket akışını izleyin!
- Çıkmak için **CTRL+C** tuşuna basın.

---

### ❗ Gereksinimler

- Linux işletim sistemi
- Python 3.x
- Root yetkisi (sudo ile çalıştırın)
- `colorama` Python paketi

---

### 🛑 Notlar

- **Windows'ta çalışmaz!** (`socket.AF_PACKET` sadece Linux'ta vardır)
- Sadece eğitim ve analiz amaçlıdır.
- Ethernet, IPv4, TCP, UDP ve ICMP paketlerini canlı ve renkli gösterir.

---

### 📝 Örnek Çıktı

```text
   _____  .__                              ________           ________                       .___
  /  _  \ |  |__  _  _______  ___.__. _____\_____  \   ____  /  _____/ __ _______ _______  __| _/
 /  /_\  \|  |\ \/ \/ /\__  \<   |  |/  ___//   |   \ /    \/   \  ___|  |  \__  \\_  __ \/ __ | 
/    |    \  |_\     /  / __ \\___  |\___ \/    |    \   |  \    \_\  \  |  // __ \|  | \/ /_/ | 
\____|__  /____/\/\_/  (____  / ____/____  >_______  /___|  /\______  /____/(____  /__|  \____ | 
        \/                  \/\/         \/        \/     \/        \/           \/           \/ 
                                                        Network Sniffer Tool / By 01fromoon

💾 Ethernet Çerçevesi: 4A:5B:6C:7D:8E:9F → 00:11:22:33:44:55 (Protokol: 8)
🌐 IPv4 Paketi: 192.168.1.5 → 142.250.186.206 (Protokol: 6, TTL: 64)
🔵 TCP: 192.168.1.5:56544 → 142.250.186.206:443
```

---

## ✨ Enjoy safe and fun packet sniffing! / Güvenli ve keyifli analizler!
