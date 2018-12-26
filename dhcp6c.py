from dhcp6 import *
from scapy.all import *
import random 

dhcp6s = DHCPv6_am()
dhcp6s.parse_options(dns="2001:500::1035", domain="localdomain, local", duid=None,
        iface=conf.iface6, advpref=255, sntpservers=None, 
        sipdomains=None, sipservers=None, 
        nisdomain=None, nisservers=None, 
        nispdomain=None, nispservers=None,
        bcmcsdomains=None, bcmcsservers=None,
        debug=1)

ether = Ether(dst="ff:ff:ff:ff:ff:ff", src="8c:85:90:39:f5:17")
ip = IPv6(dst="ff02::1:2", src="fe80::8e85:90ff:fe39:f517")
udp = UDP(dport=547,sport=546,chksum=0)
sol = DHCP6_Solicit(trid=random.randint(0,0xffffff))
cid = DHCP6OptClientId(duid=DUID_LLT())
pkt = ether/ip/udp/sol/cid
# req = IPv6(dst="::1")/UDP()/DHCP6(msgtype=1)/DHCP6OptClientId(duid=DUID_LLT())

# print(dhcp6s.make_reply(req))
req = IPv6(dst="::1")/UDP()/DHCP6(msgtype=1)/DHCP6OptClientId(duid=DUID_LLT())
assert dhcp6s.is_request(req)
res = dhcp6s.make_reply(pkt)
print('------------')
print(res.display())
send(res, iface='en0')

# assert not dhcp6s.is_request(res)
# assert res[DHCP6_Advertise]
# assert res[DHCP6OptPref].prefval == 255
# assert res[DHCP6OptReconfAccept]
# dhcp6s.print_reply(req, res)


# print("Sending discover with mac: {mac} through {iface}".format(mac=str2mac("8c:85:90:39:f5:17"), iface=conf.iface))

# p = Ether(dst="ff:ff:ff:ff:ff:ff", src="8c:85:90:39:f5:17") / IPv6(dst="ff02::2", src="fe80::8e85:90ff:fe39:f517")
# p /= ICMPv6ND_RS()
# p /= ICMPv6NDOptSrcLLAddr(lladdr=get_if_hwaddr("en0"))
# sendp(p)