# 🛡️ Python Firewall Monitor

A Python-based desktop application that uses Scapy to monitor network traffic, classify packets using rule-based filtering, and display real-time logs through a Tkinter GUI.

> ⚠️ Note: This is a monitoring and logging tool. It does NOT block packets at the OS/kernel level.

---

## 🚀 Features

* 📡 Live packet sniffing using Scapy
* 🔍 Rule-based classification (Allowed / Blocked)
* 📊 Real-time statistics (Total, Allowed, Blocked)
* 🖥️ Interactive Tkinter GUI with dark theme
* 📁 File logging for blocked events (`firewall_log.txt`)
* 🔄 Reloadable rules via `rules.json`
* 🧵 Background sniffing with threading
* 🎯 Log filtering (All / Allowed / Blocked)

---

## 🧠 How It Works

1. Captures packets using Scapy
2. Extracts details like IP, ports, and protocol
3. Compares packet data with rules in `rules.json`
4. Labels packets as:

   * ✅ Allowed
   * ❌ Blocked
5. Displays logs in GUI and writes blocked events to file

---

## 📂 Project Structure

```
project/
│── firewall.py          # Packet sniffing & rule engine
│── gui.py               # Tkinter GUI
│── rules.json           # Blocking rules
│── firewall_log.txt     # Logged blocked events
│── output.txt           # (Optional / not core)
```

---

## ⚙️ Requirements

* Python 3.x
* Scapy

Install dependencies:

```
pip install scapy
```

---

## ▶️ Usage

Run the GUI:

```
python gui.py
```

Then:

* Click **Start Monitoring** to begin sniffing
* Click **Stop Monitoring** to stop
* View live logs and stats in the dashboard

---

## 🧾 Sample `rules.json`

```
{
  "block_ips": ["192.168.1.10"],
  "block_ports": [23, 445],
  "block_protocols": ["ICMP"]
}
```

---

## 📊 Logging

* GUI: Stores logs in memory (`log_data`)
* File: Writes blocked events to `firewall_log.txt`

---

## ⚠️ Limitations

* Does NOT block packets at system level
* Requires admin/root privileges for packet sniffing
* Designed for learning and monitoring purposes

---

## 🛠️ Future Improvements

* Real packet blocking using OS firewall integration
* Advanced rule engine (CIDR, ranges, regex)
* Alerts & notifications
* Dashboard analytics (charts)
* Export logs (CSV / JSON)

---

## 👨‍💻 Author

**Krathan N Shetty**

* Cybersecurity Enthusiast | Web Developer
* GitHub: https://github.com/krathanshetty

---

## 📜 License

This project is for educational purposes.
