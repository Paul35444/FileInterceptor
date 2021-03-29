#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

#list for acknowledged field in packet
ack_list[]

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
#check packets RAW layer
    if scapy_packet.haslayer(scapy.RAW):
#check packets destination port for 80 (http)
        if scapy_packet[scapy.TCP].dport == 80:
            print("HTTP Request")
#if state to find exe files in Raw layer
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] .exe Request")
                print(scapy_packet.show())
#check packets source port for 80 (http)
        elif scapy_packet[scapy.TCP].sport == 80:
            print("HTTP Response")
            print(scapy_packet.show())

    packet.accept()

#create instance of queue
queue = netfilterqueue.NetfilterQueue()
#bind queue to queue num 0 and callback to func process_packet
queue.bind(0, process_packet)
queue.run
