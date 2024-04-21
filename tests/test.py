from scapy.all import *
from scapy.layers.inet6 import ICMPv6ND_NS
from scapy.contrib import *

srcIpv6 = "::1"
dstIpv6 = "::1"

def sendNdp():
    ns = ICMPv6ND_NS(tgt=dstIpv6)

    ll_addr = "00:01:02:03:04:05"
    scr_ll_opt = ICMPv6NDOptSrcLLAddr(lladdr=ll_addr)
    ip6 = IPv6(src=srcIpv6, dst=dstIpv6)

    packet = ip6 / ns / scr_ll_opt

    send(packet)

sendNdp()

