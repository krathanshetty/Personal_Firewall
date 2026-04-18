import json
import logging
import os
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP

logging.basicConfig(filename='firewall_log.txt', level=logging.INFO, format='%(asctime)s %(message)s')

ROOT_DIR = os.path.dirname(__file__)
RULES_PATH = os.path.join(ROOT_DIR, 'rules.json')

stop_sniff_event = threading.Event()
log_data = []
rules = {}


def load_rules():
    global rules
    try:
        with open(RULES_PATH, 'r', encoding='utf-8') as f:
            rules = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        rules = {"block_ips": [], "block_ports": [], "block_protocols": []}
    return rules


load_rules()


def check_packet(packet):
    reason = ""
    if IP in packet:
        if packet[IP].src in rules.get("block_ips", []):
            reason = f"Blocked IP: {packet[IP].src}"
    if TCP in packet or UDP in packet:
        sport, dport = packet.sport, packet.dport
        if sport in rules.get("block_ports", []) or dport in rules.get("block_ports", []):
            reason = f"Blocked Port: {sport}/{dport}"
    if ICMP in packet and "ICMP" in rules.get("block_protocols", []):
        reason = "Blocked Protocol: ICMP"

    summary = packet.summary()
    if reason:
        log_entry = f"❌ {summary} - {reason}"
        logging.info(log_entry)
    else:
        log_entry = f"✅ {summary}"
    log_data.append(log_entry)


def start_sniffing():
    stop_sniff_event.clear()
    sniff(prn=check_packet, store=False, stop_filter=lambda packet: stop_sniff_event.is_set())


def stop_sniffing():
    stop_sniff_event.set()
    logging.info("Stopped sniffing")