# 🔥 V-SHIELD IDS/IPS FIREWALL

A lightweight Python-based Intrusion Detection and Prevention System (IDS/IPS) built using Scapy for real-time network monitoring and basic DoS attack mitigation.

---

## 🛠 System Requirements

- OS: Kali Linux (recommended)
- Python 3.x
- Root privileges (required for packet sniffing and firewall rules)
- Active network interface (`eth0` / `ens33` / `wlan0`)

---

## 📥 Installation Steps

### 1. Clone Repository

```bash
git clone https://github.com/vedanthbn2/v-shield-firewall1.git
cd v-shield-firewall
```

### 2. Give Execution Permissions

```bash
chmod +x setup.sh
chmod +x run.sh
```

### 3. Install Dependencies

```bash
bash setup.sh
```

This installs:
- `python3`
- `scapy`
- `colorama`
- `iptables`

---

## ⚙️ Configuration

### Check Network Interface

```bash
ip a
```

Look for your active interface: `eth0`, `ens33`, or `wlan0`

### Update Interface in `firewall.py`

```python
INTERFACE = "eth0"
```

Change if needed:

```python
INTERFACE = "ens33"
```

---

## ▶️ Running the Firewall

```bash
sudo ./run.sh
```

### 🎯 Expected Output


---

## 🧪 Testing the Firewall

### Generate Traffic

```bash
ping <firewall-ip>
```

Or continuous traffic:

```bash
while true; do ping -c 1 <firewall-ip>; done
```

### Detection Output


---

## 🔐 Firewall Behavior

- Monitors incoming traffic
- Detects high packet rate (DoS behavior)
- Blocks attacker IP using `iptables`
- Automatically unblocks after defined time

---

## ⚠️ Important Notes

- Must run using `sudo`
- Works best in lab environments
- Designed for basic DoS detection (not full DDoS protection)
- Interface must be configured correctly

---

## ❗ Troubleshooting

**No detection — check interface:**
```bash
ip a
```

**No packets captured:**
```bash
sudo tcpdump -i eth0
```

**Permission error:**
```bash
sudo ./run.sh
```

**Firewall not blocking:**
```bash
sudo iptables -L
```

---

## 🧠 Project Description

V-SHIELD is a lightweight IDS/IPS system that monitors network traffic in real time, detects anomalous behavior such as DoS attacks, and dynamically blocks malicious IP addresses using system-level firewall rules.

---

## 👨‍💻 Author

**Vedanth Shetty**
Cybersecurity Project – IDS/IPS Firewall


