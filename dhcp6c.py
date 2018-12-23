from dhcp6 import *
from scapy.all import *

if __name__ == "__main__":
    dhcp6c = DHCPv6_am()
    print(dhcp6c.duid)
    sol = DHCP6_Solicit()
    opreq = DHCP6OptOptReq()
    et= DHCP6OptElapsedTime()
    cid = DHCP6OptClientId()
    iana = DHCP6OptIA_NA()
    optiana = DHCP6OptIAAddress()

    l3 = Ether (dst="ff:ff:ff:ff:ff:ff", src = RandMAC())
    l2 = IPv6(dst=dstt, src=srcc)
    pkt = l2/l3/sol/cid/opreq/et/iana
    sendp(pkt, iface='eth0')