#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload()):
#check packets RAW layer
    if scapy_packet.haslayer(scapy.RAW):
        print(scapy_packet.show())

    packet.accept()

