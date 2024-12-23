from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
import random
import time
import sys

# Client configuration
if(len(sys.argv) < 2):
    print("Provide interface name!")
    exit(1)

macs = {
    "vt-yellow": "4a:3f:60:a1:7f:6c",
    "vt-blue": "92:12:95:09:eb:14",
    "vt-green": "46:93:6e:42:86:91"
}

iface = sys.argv[1]
client_mac = macs[sys.argv[1]]
transaction_id = random.randint(1, 0xFFFFFFFF)  # Random transaction ID

RETRY_DISCOVER = 10

renewal_ts = 0
discover_ts = 0
offer_pkt = None

def validate_ts():
    while True:
        global renewal_ts
        global discover_ts
        global offer_pkt

        if(renewal_ts != 0 and time.time() > renewal_ts):
            renewal_ts = 0
            send_dhcp_request(offer_pkt, True)
            print("[INFO] renewal_ts passed! DHCP Request sent!")

        if(discover_ts != 0 and time.time() > discover_ts):
            discover_ts = time.time() + RETRY_DISCOVER
            send_dhcp_discover()
            print("[INFO] discover_ts passed! DHCP Discover sent!")

        time.sleep(1)



def send_dhcp_discover():
    """Sends a DHCP Discover packet."""
    ether = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(chaddr=[mac2str(client_mac)], xid=transaction_id, flags=0x8000)
    dhcp = DHCP(options=[("message-type", "discover"), "end"])
    discover_pkt = ether / ip / udp / bootp / dhcp

    print(f"[INFO] Sending DHCP Discover with MAC: {client_mac}")
    sendp(discover_pkt, iface=iface, verbose=0)


def send_dhcp_request(offer_pkt, unicast=False):
    """Sends a DHCP Request packet based on the received DHCP Offer."""
    offered_ip = offer_pkt[BOOTP].yiaddr
    server_ip = offer_pkt[DHCP].options[3][1]  # Get the DHCP server IP address
    server_mac = offer_pkt[Ether].src

    ether = Ether(src=client_mac, dst=server_mac if unicast else "ff:ff:ff:ff:ff:ff")
    ip = IP(src="0.0.0.0", dst=server_ip if unicast else "255.255.255.255")
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(op=1, chaddr=[mac2str(client_mac)], ciaddr="0.0.0.0", yiaddr=offer_pkt[BOOTP].yiaddr, xid=transaction_id)
    dhcp = DHCP(options=[
        ("message-type", "request"),
        ("server_id", server_ip),
        ("requested_addr", offered_ip),
        "end"
    ])
    request_pkt = ether / ip / udp / bootp / dhcp

    print(f"[INFO] Sending DHCP Request for IP address: {offered_ip}")
    sendp(request_pkt, iface=iface, verbose=0)


def handle_dhcp_response(pkt):
    """Processes a DHCP response packet."""
    global renewal_ts
    global discover_ts
    global offer_pkt

    if DHCP in pkt and pkt[DHCP].options[0][1] == 2:  # DHCP Offer
        print(f"[INFO] Received DHCP Offer with IP: {pkt[BOOTP].yiaddr}")
        discover_ts = 0
        offer_pkt = pkt
        send_dhcp_request(pkt)

    elif DHCP in pkt and pkt[DHCP].options[0][1] == 5:  # DHCP Ack
        print(f"[INFO] Received DHCP Ack. Assigned IP address: {pkt[BOOTP].yiaddr}")
        print(f"[INFO] {pkt[DHCP].options}")
        renewal_ts = time.time() + (pkt[DHCP].options[2][1]) / 2
        discover_ts = time.time() + (pkt[DHCP].options[2][1])


def start_dhcp_client():
    """Starts the DHCP client."""
    print("[INFO] DHCP client started.")

    lease_time_thread = threading.Thread(target=validate_ts)
    lease_time_thread.daemon = True
    lease_time_thread.start()

    send_dhcp_discover()

    sniff(filter="udp and (port 67 or port 68)", prn=handle_dhcp_response, iface=iface)
    print("[ERROR] No response from DHCP server.")


if __name__ == "__main__":
    start_dhcp_client()
