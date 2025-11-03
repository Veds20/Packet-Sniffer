# 🕵️‍♂️ Packet Sniffer (with GUI)

A lightweight **packet sniffer** built using **Python (FastAPI)** and a modern **dark-themed web interface**.  
It captures live network packets and displays basic details such as **Time, Size, IPv4/6, and Protocol**.

---

## ⚙️ Features
- Real-time packet capturing using raw sockets
- FastAPI backend with WebSocket communication
- Modern web UI
- Displays: Time, Size, IP version, Protocol
- Demonstrates OS-level concepts (system calls, threading, and I/O)

---

## 🧠 OS Concepts Covered
- System Calls (`socket`, `recvfrom`)
- Multithreading and concurrency
- Network I/O management
- Process communication (WebSocket)
- Kernel-level packet handling

---

## 🚀 How to Run

```bash
pip install fastapi uvicorn
python app.py
