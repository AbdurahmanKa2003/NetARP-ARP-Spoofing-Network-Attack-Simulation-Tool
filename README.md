# ⚠️ NetARP — ARP Spoofing & Network Attack Simulation Tool

NetARP is an educational cybersecurity project written in Python that demonstrates ARP spoofing and Man-in-the-Middle (MITM) attacks in local area networks.

The project helps students and security researchers understand ARP protocol weaknesses, traffic redirection techniques, and network exploitation methods in controlled environments.

⚠ This tool is intended for academic research and authorized security testing only.

---

## 📁 Project Structure

```
NetARP/
│
├── arp.py
└── README.md
```

---

## 🚀 Core Features

### ARP Attack Simulation
- ARP cache poisoning
- Gateway and victim impersonation
- MITM traffic redirection
- Continuous ARP response injection

### Network Control
- MAC address discovery
- Dynamic target identification
- Interface-based communication
- Real-time spoofing loop

### Recovery System
- Automatic ARP table restoration
- Safe termination handling
- Network stability protection

---

## 🧩 Technologies Used

- Python 3.x
- Scapy
- Linux Networking Stack
- Raw Packet Processing

---



## ▶️ Usage

Administrator privileges are required.

```bash
sudo python arp.py
```

With arguments:

```bash
sudo python arp.py --target 192.168.1.15 --gateway 192.168.1.1
```

---

## 🔄 Attack Architecture

```
Victim ⇄ Attacker ⇄ Router
```

1. The attacker sends fake ARP responses.
2. Victim associates gateway IP with attacker MAC.
3. Router associates victim IP with attacker MAC.
4. Traffic is redirected through attacker.
5. MITM position is maintained.

---

## 📚 Security Topics Covered

- Address Resolution Protocol (ARP)
- ARP cache poisoning
- Man-in-the-Middle attacks
- Network layer exploitation
- Traffic interception
- Secure protocol importance
- TLS-based protection

---

## ⚠️ Legal and Ethical Notice

This tool must only be used in environments with explicit authorization.

Unauthorized use is illegal and may lead to criminal liability.

The author is not responsible for misuse.

---

## 🎓 Educational Purpose

This project is designed to help learners:

- Analyze network vulnerabilities
- Understand MITM techniques
- Practice ethical hacking
- Improve defensive awareness
- Develop penetration testing skills

---

## 📈 Future Enhancements

- Integrated traffic sniffer
- MITM packet modification
- Detection mode
- Logging system
- GUI interface
- Multi-target support

---

## 👨‍💻 Author

Developed for cybersecurity education.

Specialization: Cybersecurity Engineering  

---

## 📄 License

MIT License

Educational and research use only.
