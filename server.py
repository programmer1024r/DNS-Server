from scapy.all import *
from scapy.layers.dns import *
from sniff_functions import *
from DB_functions import *
from consts import MY_IPV4


def run():

    print("Welcome Re'ems DNS server")
    print(f"[Sniffing on]: {MY_IPV4}")

    parse_DB()
    # ---------------------- First conversation -----------------------
    packets = sniff(count=1, lfilter=is_PTR_DNS, prn=print_packet) 
    dns_request = packets[0]    
    
    # Generate first respond
    respond = generate_respond(MY_IPV4, dns_request)
    respond[DNSRR].rdata = "Reem's Domain"
    
    respond.show()
    send(respond)
    # -----------------------------------------------------------------

    # ---------------------- Second conversation ----------------------
    packets = sniff(count=1, lfilter=is_PTR_DNS, prn=print_packet)
    dns_request = packets[0] # third packet
    dns_request.show()
    dns_request[DNSQR].qname.decode()
    # Generate second respond
    respond = generate_respond(MY_IPV4, dns_request)
    
    # -----------------------------------------------------------------
# Make this file act like a library
if __name__ == "__main__":
    run()
    