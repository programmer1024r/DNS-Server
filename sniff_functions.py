import socket
from scapy.all import *
from scapy.layers.dns import *
from consts import MY_IPV4
import re

def get_searched_domain(dns_request):
    """
    Use: 
    Input: 
    Output: 
    """
    domain_to_search = dns_request[DNSQR].qname.decode()
    try:
        found = re.search('(.+?).in-addr.arpa.', domain_to_search).group(1)
    except AttributeError:
    
        found = '' # apply your error handling
    
    return found

def is_PTR_DNS(packet):
    """
    Use: check if a packet is dns ptr
    Input: packet
    Output: if it is or not
    """
    return ((DNS in packet) and (DNSQR in packet) and (DNSRR not in packet) and (UDP in packet) and (IP in packet) and
             (packet[IP].dst == MY_IPV4) and (packet[UDP].dport == 53) and (packet[DNSQR].qtype == 12 or packet[DNSQR].qtype == 1))

def print_packet(packet):
    """
    Use: print a packet content
    Input: packet
    Output: None
    """
    print(packet.show())

def generate_respond(ip, dns_request):
    """
    Use: generate a dns respond
    Input: my ip, dns_request
    Output: the dns respond
    """
    return IP(dst=dns_request[IP].src, src=MY_IPV4) \
    / UDP(dport=dns_request[UDP].sport, sport=53) \
    / DNS(id=dns_request[DNS].id, qr=1, qd=dns_request[DNSQR], an=DNSRR(rrname=dns_request[DNSQR].qname, type=dns_request[DNSQR].qtype, ttl=128))