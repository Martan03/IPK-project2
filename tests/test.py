from scapy.all import *
import subprocess

binary = "../ipk-sniffer"
iface = ["-i", "lo"]

src_ip = "127.0.0.1"
dst_ip = "127.0.0.1"
src_ip6 = "::1"
dst_ip6 = "::1"

# UDP packet sending with IPv4 and IPv6
def send_udp():
    ip = IP(dst=dst_ip)
    udp = UDP(dport=5678)
    data = "Testing UDP"

    send(ip / udp / data)

def send_udp6():
    ip = IPv6(dst=dst_ip6)
    udp = UDP(dport=12345)
    data = "Testing IPv6 UDP"

    send(ip / udp / data)

# TCP packet sending with IPv4 and IPv6
def send_tcp():
    ip = IP(dst="127.0.0.1")
    tcp = TCP(dport=4567, flags='S')
    data = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"

    send(ip / tcp / data)

def send_tcp6():
    ip = IPv6(src=src_ip6, dst=dst_ip6)
    tcp = TCP(dport=4567)
    data = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"

    send(ip / tcp / data)

# ICMP4 packet sending
def send_icmp():
    send(IP(dst=dst_ip) / ICMP())

# ICMP6 packet sending
def send_icmp6():
    send(IPv6(dst=dst_ip6) / ICMPv6EchoRequest())

# ARP packet sending
def send_arp():
    send(ARP(pdst=dst_ip))

# NDP packet sending
def send_ndp():
    ns = ICMPv6ND_NS()
    ip6 = IPv6(dst=dst_ip6)

    send(ip6 / ns)

def send_ndp_rs():
    rs = ICMPv6ND_RS()
    ip6 = IPv6(dst=dst_ip6)

    send(ip6 / rs)

# MLD packet sending
def send_mld():
    ip = IPv6(dst=dst_ip6)

    send(ip / ICMPv6MLQuery())


def run_sniffer(args):
    try:
        return subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    except Exception as e:
        print("Error: ", e)
        return None

def wait_sniffer(process):
    try:
        stdout, stderr = process.communicate()
        return stdout, stderr
    except Exception as e:
        print("Error: ", e)
        return None, None

def check_stdout(stdout, stderr, values):
    if stdout is None:
        print("Failure: stdout is None")
        return

    tgt = stdout.decode('utf-8')
    err = stderr.decode('utf-8')
    for s in values:
        if s not in tgt:
            print("Failure:", s, "not in stdout")
            print("stdout:\n", tgt)
            print("stderr:\n", err)
            return

    print("Success")

def test(name, args, isend, psend, exp):
    exec = [binary] + iface

    print(name)
    process = run_sniffer(exec + args)
    time.sleep(0.2)
    isend()
    psend()
    stdout, stderr = wait_sniffer(process)
    check_stdout(stdout, stderr, exp)
    print()

test(
    "UDP test",
    ["-u", "-p", "5678"],
    send_tcp,
    send_udp,
    ["dst IP: 127.0.0.1", "dst port: 5678"]
)

test(
    "UDP IPv6 test",
    ["--udp", "--port-destination", "12345"],
    send_tcp6,
    send_udp6,
    ["src IP: ::1", "dst port: 12345"]
)

test(
    "TCP test",
    ["-t", "-p", "4567"],
    send_udp,
    send_tcp,
    ["dst IP: 127.0.0.1", "dst port: 4567"]
)

test(
    "TCP IPv6 test",
    ["--tcp", "--port-destination", "4567"],
    send_udp6,
    send_tcp6,
    ["src IP: ::1", "dst port: 4567"]
)

test(
    "ICMP test",
    ["--icmp4"],
    send_arp,
    send_icmp,
    ["src IP: 127.0.0.1"]
)

test(
    "ICMP6 test",
    ["--icmp6"],
    send_icmp,
    send_icmp6,
    ["dst IP: ::1"]
)

test(
    "ARP test",
    ["--arp"],
    send_tcp,
    send_arp,
    ["src MAC: 00:00:00:00:00:00", "dst MAC: FF:FF:FF:FF:FF:FF"]
)

test(
    "NDP test",
    ["--ndp"],
    send_mld,
    send_ndp,
    ["dst IP: ::1", "dst MAC: FF:FF:FF:FF:FF:FF"]
)

test(
    "NDP rs test",
    ["--ndp"],
    send_icmp,
    send_ndp_rs,
    ["dst IP: ::1"]
)

test(
    "MLD test",
    ["--mld"],
    send_icmp6,
    send_mld,
    ["dst IP: ::1"]
)
