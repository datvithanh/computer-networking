from dhcp6 import *
from scapy.all import *

# if __name__ == "__main__":
#     dhcp6c = DHCPv6_am()
#     sol = DHCP6_Solicit()
#     opreq = DHCP6OptOptReq()
#     et= DHCP6OptElapsedTime()
#     cid = DHCP6OptClientId()
#     iana = DHCP6OptIA_NA()
#     optiana = DHCP6OptIAAddress()

#     l3 = Ether (dst="ff:ff:ff:ff:ff:ff", src = RandMAC())
#     l2 = IPv6(dst=dstt, src=srcc)
#     pkt = l2/l3/sol/cid/opreq/et/iana
#     sendp(pkt, iface='eth0')

# l3 = Ether(dst="ff:ff:ff:ff:ff:ff",src=RandMAC())
# l2 = IPv6(dst="ff02::1:2", src="::0")
# l1 = UDP(dport=547)
# sol = DHCP6_Solicit()
# send(l3/l2/l1/sol)

sol = DHCP6_Solicit()
# opreq = DHCP6OptOptReq()
# et = DHCP6OptElapsedTime()
cid = DHCP6OptClientId()
# iana = DHCP6OptIA_NA()
# optiana = DHCP6OptIAAddress()

ether = Ether(dst="ff:ff:ff:ff:ff:ff", src="8c:85:90:39:f5:17")
ip = IPv6(dst="ff02::1:2", src="::0")
udp = UDP(dport=547,sport=546)
# addr = raw_input("Give Option Address: ")
# optiana.addr = str(RandIP6(addr))
pkt = ether/ip/udp/sol/cid#/opreq/et/iana
sendp(pkt)#, iface='en0')

# eth.addr == ff:ff:ff:ff:ff:ff