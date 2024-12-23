from scapy.all import *
from scapy.layers.dhcp import DHCP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
import time
import threading

server_ip = "192.168.1.1"
subnet_mask = "255.255.255.0"
lease_time = 10  # Lease time in seconds (default: 10 seconds)
dns_server = "8.8.8.8"
ip_pool = [f"192.168.1.{i}" for i in range(10, 20)]  # IP pool for leasing
allocated_ips = {}  # Stores {MAC: {"ip": IP, "expiry": timestamp}}
iface = "vt-red"

def handle_dhcp(pkt):
    """Handles incoming DHCP packets (Discover and Request)."""
    if pkt[DHCP] and pkt[DHCP].options[0][1] == 1:  # DHCP Discover
        print(f"[INFO] Received DHCP Discover from {pkt[Ether].src}")
        offer_ip = allocate_ip(pkt[Ether].src)
        if offer_ip:
            send_dhcp_offer(pkt, offer_ip)
        else:
            print("[ERROR] No available IP addresses in the pool.")

    elif pkt[DHCP] and pkt[DHCP].options[0][1] == 3:  # DHCP Request
        print(f"[INFO] Received DHCP Request from {pkt[Ether].src}")
        if pkt[BOOTP].ciaddr == "0.0.0.0":
            requested_ip = pkt[BOOTP].yiaddr
        else:
            requested_ip = pkt[BOOTP].ciaddr

        if validate_ip_request(requested_ip, pkt[Ether].src):
            allocated_ips[pkt[Ether].src] = {"ip": requested_ip, "expiry": time.time() + lease_time}
            send_dhcp_ack(pkt, requested_ip)
        else:
            print("[ERROR] Requested IP is unavailable or not valid.")


def allocate_ip(mac_address):
    """Allocates an IP address to the given MAC address."""
    if mac_address in allocated_ips:
        # Return already allocated IP if lease is still valid
        if allocated_ips[mac_address]["expiry"] > time.time():
            return allocated_ips[mac_address]["ip"]
        else:
            # Expired lease: remove the entry and reallocate
            del allocated_ips[mac_address]

    # Find the first available IP in the pool
    for ip in ip_pool:
        if ip not in [entry["ip"] for entry in allocated_ips.values()]:
            return ip
    return None


def validate_ip_request(requested_ip, mac_address):
    """Validates whether the requested IP is available or already allocated."""
    if requested_ip in ip_pool:
        # Check if the IP is either free or already allocated to the same MAC
        if (requested_ip not in [entry["ip"] for entry in allocated_ips.values()]
                or allocated_ips.get(mac_address, {}).get("ip") == requested_ip):
            return True
    return False


def send_dhcp_offer(pkt, offer_ip):
    """Sends a DHCP Offer packet with the offered IP address."""
    time.sleep(1)
    ether = Ether(src=get_if_hwaddr(iface), dst=pkt[Ether].src)
    ip = IP(src=server_ip, dst="255.255.255.255")
    udp = UDP(sport=67, dport=68)
    bootp = BOOTP(op=2, yiaddr=offer_ip, siaddr=server_ip, chaddr=pkt[BOOTP].chaddr)
    dhcp = DHCP(options=[
        ("message-type", "offer"),
        ("subnet_mask", subnet_mask),
        ("lease_time", lease_time),
        ("server_id", server_ip),
        ("router", server_ip),
        ("name_server", dns_server),
        "end"
    ])
    offer_pkt = ether / ip / udp / bootp / dhcp
    sendp(offer_pkt, iface=iface, verbose=0)
    print(f"[INFO] Sent DHCP Offer for {offer_ip}")


def send_dhcp_ack(pkt, ack_ip):
    """Sends a DHCP Acknowledge packet confirming the IP lease."""
    time.sleep(1)
    ether = Ether(src=get_if_hwaddr(iface), dst=pkt[Ether].src)
    ip = IP(src=server_ip, dst="255.255.255.255")
    udp = UDP(sport=67, dport=68)
    bootp = BOOTP(op=2, yiaddr=ack_ip, siaddr=server_ip, chaddr=pkt[BOOTP].chaddr)
    dhcp = DHCP(options=[
        ("message-type", "ack"),
        ("subnet_mask", subnet_mask),
        ("lease_time", lease_time),
        ("server_id", server_ip),
        ("router", server_ip),
        ("name_server", dns_server),
        "end"
    ])
    ack_pkt = ether / ip / udp / bootp / dhcp
    sendp(ack_pkt, iface=iface, verbose=0)
    print(f"[INFO] Sent DHCP Acknowledge for {ack_ip}")


def lease_expiry_handler():
    """Background thread to monitor and handle expired leases."""
    while True:
        current_time = time.time()
        expired_leases = [mac for mac, lease in allocated_ips.items() if lease["expiry"] <= current_time]

        for mac in expired_leases:
            print(f"[INFO] Lease expired for MAC: {mac}, releasing IP: {allocated_ips[mac]['ip']}")
            del allocated_ips[mac]  # Remove expired lease

        time.sleep(10) 


def start_dhcp_server():
    """Starts the DHCP server and lease expiry handler."""
    print(f"[INFO] DHCP Server running on {server_ip}")

    # Start lease expiry threa
    lease_thread = threading.Thread(target=lease_expiry_handler, daemon=True)
    lease_thread.start()

    sniff(filter="udp and (port 67 or port 68)", prn=handle_dhcp, iface=iface)


if __name__ == "__main__":
    start_dhcp_server()
