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
print('------------')

class DHCPv6_client():
    def __init__(self, iface="en0", ipv6=None, mac=None, mac_mcast="33:33:00:01:00:02"):
        if mac is None:
            mac = get_if_hwaddr(iface)

        self._mac = mac
        self._mac_mcast = mac_mcast
        self._iface = iface
        self._server_ip = None
        self._ipv6 = self.mac2ipv6()


    def mac2ipv6(self):
        # only accept MACs separated by a colon
        mac = self._mac
        parts = mac.split(":")

        # modify parts to match IPv6 value
        parts.insert(3, "ff")
        parts.insert(4, "fe")
        parts[0] = "%x" % (int(parts[0], 16) ^ 2)

        # format output
        ipv6Parts = []
        for i in range(0, len(parts), 2):
            ipv6Parts.append("".join(parts[i:i+2]))
        ipv6 = "fe80::%s/64" % (":".join(ipv6Parts))
        return ipv6

    def print_pkt(self, pkt):
        print(pkt.display())
        print('---------------------------------')

    def request_fresh_lease(self):
        trid = random.randint(0, 0xffffff)
        ether = Ether(src=self._mac, dst=self._mac_mcast)

        ip = IPv6(src=self._ipv6, dst="ff02::1:2")
        udp = UDP(dport=547, sport=546, chksum=0)
        #solicit
        solicit_pkt = ether/ip/udp/DHCP6_Solicit(trid=trid)/DHCP6OptClientId(duid=DUID_LLT())
        #advertise
        advertise = dhcp6s.make_reply(solicit_pkt)
        #info request
        request_pkt = ether/ip/udp/DHCP6_Request(trid=trid)/DHCP6OptClientId(duid=DUID_LLT())/DHCP6OptServerId(duid=dhcp6s.duid)
        #reply
        reply = dhcp6s.make_reply(request_pkt)
        #release
        release_pkt = ether/ip/udp/DHCP6_Release(trid=trid)/DHCP6OptClientId(duid=DUID_LLT())/DHCP6OptServerId(duid=dhcp6s.duid)
        #reply release 
        reply_release = dhcp6s.make_reply(release_pkt)
        
        self.print_pkt(solicit_pkt)
        self.print_pkt(advertise)
        self.print_pkt(request_pkt)
        self.print_pkt(reply)
        self.print_pkt(release_pkt)

        # assert sendp(solicit_pkt, iface="en0")
        # assert sendp(request_pkt, iface="en0")
        # assert sendp(release_pkt, iface="en0")
        # self.print_pkt(reply_release)

    def request_old_lease(self):
        pass

if __name__ == "__main__":
    client = DHCPv6_client()
    client.request_fresh_lease()
