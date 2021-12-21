from scapy.all import *
from scapy.layers.dns import *
import socket
my_IPv4 = socket.gethostbyname(socket.gethostname())
#(packet[IP].dst == my_IPv4) and
#
def is_PTR_DNS(packet):
    """
    Use: check if a packet is dns ptr
    Input: packet
    Output: if it is or not
    """
    return ((DNS in packet) and (DNSQR in packet) and (DNSRR not in packet) and (UDP in packet) and (IP in packet) and
             (packet[IP].dst == "10.100.102.26") and (packet[UDP].dport == 53))

def print_packet(packet):
    """
    Use: print a packet content
    Input: packet
    Output: None
    """
    print(packet.show())

def save_to_data():
    """
    Use: save 
    Input: packet
    Output: None
    """

def run():

    print("Welcome To the best DNS server you will ever run")

    sniff(lfilter=is_PTR_DNS, prn=print_packet)    

# Make this file act like a library
if __name__ == "__main__":
    print(my_IPv4)
    run()
    