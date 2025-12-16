# 🔐 ARP Spoofing Detector and Alert System

A Python-based cybersecurity project that detects **ARP spoofing / ARP poisoning attacks** by monitoring the local ARP table and identifying **duplicate MAC address mappings**. The system provides a **user-friendly GUI**, logs suspicious activity in real time, and sends **email alerts** to the administrator.

This project is designed for **defensive security**, academic learning, and controlled lab demonstrations.

---

## 📌 Problem Statement

ARP (Address Resolution Protocol) does not provide authentication. Attackers can exploit this weakness by associating their MAC address with multiple IP addresses, leading to **Man-in-the-Middle (MITM)** attacks.

The goal of this project is to:
- Detect ARP spoofing without relying on packet sniffing or MITM success
- Alert administrators immediately when suspicious behavior is found

---

## 🎯 Objective

- Monitor the local ARP table continuously
- Detect if **multiple IP addresses resolve to the same MAC address**
- Treat such behavior as potential ARP spoofing
- Notify the administrator via email
- Log incidents for analysis and reporting

---

## 🚀 Features

- ✅ Real-time ARP table monitoring  
- ✅ Detection of duplicate IP–MAC mappings  
- ✅ Interactive GUI using Tkinter  
- ✅ MP4 video background for enhanced UI  
- ✅ Live monitoring log panel  
- ✅ Email alert notification to admin  
- ✅ CSV-based logging for forensics  
- ✅ Works even when MITM sniffing is blocked  

---

## 🛠️ Technologies Used

- **Python 3**
- **Tkinter** – GUI development
- **Pillow (PIL)** – UI overlays and graphics
- **OpenCV** – MP4 video background rendering
- **Scapy** – Network and ARP utilities
- **SMTP (smtplib)** – Email alert system
- **CSV / Subprocess** – Logging and ARP table scanning

---

## 🧠 Detection Logic

The detector works using the following rule:

1. Scan the local ARP table (`arp -a` / `ip neigh`)
2. Build an IP → MAC mapping
3. Reverse it to MAC → IP list
4. If **one MAC address maps to more than one IP**, flag it as suspicious
5. Trigger alerts and logging

### Example:
```
10.52.102.85 → 08:01:56:d1:g8:8d
10.52.102.236 → 08:01:56:d1:g8:8d
```


# ➡️ **ARP Spoofing Detected**

---

## 🖥️ User Interface Overview

- **Start Monitoring** – Begins ARP table scanning
- **Stop Monitoring** – Stops background detection
- **View Logs** – Opens stored CSV log records
- **Live ARP Monitor Log** – Displays real-time detection messages
- **Video Background** – Enhances user interaction

---

## 📧 Email Alert

When ARP spoofing is detected, an email is sent containing:
- Time of detection
- Suspicious MAC address
- Associated IP addresses
- System information



## 📂 Project Structure
```
ARP-SPOOFING-DETECTOR/
│
├── arp_detector.py
├── background.mp4
├── arp_logs.csv
├── README.md
└── requirements.txt
```
---

## ▶️ How to Run

### 1️⃣ Install Dependencies
```bash
pip install scapy pillow opencv-python
```
### 2️⃣ Run the Application
``` bash
  python arp_detector.py
```
``` 
⚠️ Run as Administrator / Root for ARP access.
```  
## ⚠️ Important Notes

Modern Wi-Fi adapters and routers may block MITM attacks

This detector does not rely on sniffing or poisoning

Works reliably in:

Enterprise Wi-Fi

NAT environments

Virtualized labs

Designed for defensive and educational use only

## 📈 Future Enhancements
PDF incident report generation

MAC address whitelisting

Auto attacker IP blocking

Machine learning–based anomaly detection

SIEM integration

## 🎓 Academic Use

This project is suitable for:

Cybersecurity mini/major projects

Network security labs

ARP protocol demonstrations

Defensive security research

## ⚖️ Disclaimer
This tool is intended only for educational and defensive security purposes.
Do not use it on networks you do not own or have permission to monitor.

## 👤 Author
Mourya Sagar
Cybersecurity & Network Security Enthusiast
