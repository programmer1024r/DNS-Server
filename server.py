from scapy.all import *
from scapy.layers.dns import *
from sniff_functions import *
from DB_functions import *
from consts import MY_IPV4


def run():

    print("Welcome Re'ems DNS server")
    print(f"[Sniffing on]: {MY_IPV4}")

    parse_DB()
    packets = sniff(count=1, lfilter=is_PTR_DNS, prn=print_packet) 
    dns_request = packets[0]    
    
    # Generate first respond
    respond = generate_respond(MY_IPV4, dns_request)
    respond[DNSRR].rdata = "Reem's Domain"
    
    print(respond.show())
    send(respond)
# Make this file act like a library
if __name__ == "__main__":
    run()
    