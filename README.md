# Network Packet Analyzer v2.0 🕵️‍♂️🌐

A lightweight, GUI-based network packet sniffing tool developed in Python. It captures network traffic in real-time, displays source/destination IPs, ports, and protocols, and allows you to export the captured data to a CSV file.

Developed by: Sriman Kundu | Educational Use Only

---

## ⚠️ IMPORTANT: Packet Capture Prerequisites

Before using this tool, your system needs the ability to capture raw network packets from your network interface.

* **Windows Users:** Standard Windows drivers cannot capture raw packets by default. You MUST install a packet sniffing driver for this tool to work.
  1. Download **Npcap** from https://npcap.com
  2. Run the installer.
  3. **CRITICAL:** During installation, check the box that says "Install Npcap in WinPcap API-compatible Mode".
  4. Restart your computer.

* **Linux Users:** Packet capture libraries (`libpcap`) are usually pre-installed on Linux. You simply need to ensure you run the tool with `root` privileges.

---

## 🪟 How to Run on Windows

### Option 1: The Easy Way (Using the .exe)
You do not need Python installed to use this method.
1. Download the `net.exe` file from this repository.
2. Ensure you have installed Npcap (see prerequisites above).
3. Right-click `net.exe` and select **"Run as Administrator"** (Packet sniffing requires admin rights).

### Option 2: Running from Source
If you are a developer and want to run the raw Python code:
1. Ensure Python 3 is installed.
2. Clone this repository and open the folder in PowerShell.
3. Install the required Python libraries:
   pip install -r requirements.txt
4. Ensure Npcap is installed.
5. Run the script as Administrator:
   python net.py

---

## 🐧 How to Run on Linux (Ubuntu / Kali / Debian)

Linux handles packet capture natively, so you just need to run the Python script.

1. Clone the repository and navigate to the folder:
   git clone https://github.com/sriman-git09/network_analyse_V2.0.git
   cd network_analyse_V2.0/network_analyse_V2.0-main

2. Install the required Python dependencies:
   pip3 install -r requirements.txt
   *(Note: If your Linux distro restricts pip, use your package manager: sudo apt install python3-scapy python3-requests)*

3. Run the analyzer with root privileges:
   sudo python3 net.py

---

## 📦 Requirements
If you are running the tool from the source code, your environment must have the following Python packages installed (listed in `requirements.txt`):
* scapy
* requests




## 📊 The CSV Export Feature: What is it and How to Use It?

This tool includes a powerful **Export CSV** feature, making it a professional, investigation-ready application just like Wireshark or Splunk!

### What is a CSV File?
CSV stands for **Comma-Separated Values**. It is a simple text file format used to store data in a structured, table form where each value is separated by a comma. 

### How It Works in This Tool
When you click the **Export CSV** button in the GUI, the analyzer takes all the live captured packet data and saves it into a file named `captured_packets.csv`. 

Example of the output format:
```csv
No,Time,Source IP,Src Port,Destination IP,Dst Port,Protocol,Size
1,13:55:01,192.168.1.5,443,142.250.190.78,51543,TCP,98
