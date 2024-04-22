using PacketDotNet;
using PacketDotNet.Utils;
using SharpPcap;

public class Sniffer {
    private Args Args { get; set; }

    public Sniffer(Args args) {
        Args = args;
    }

    /// <summary>
    /// Prints info about the packet
    /// </summary>
    /// <param name="rc">RawCapture</param>
    /// <returns>True when packet in filter, else false</returns>
    public bool Info(RawCapture rc) {
        var sp = HandleLinkTypes(rc);
        if (sp is null)
            return false;

        Console.WriteLine($"{sp}");
        return true;
    }

    private SniffPacket? HandleLinkTypes(RawCapture rc) {
        var sp = new SniffPacket(rc.Timeval.Date, rc.Data.Length);

        var byteSegment = new ByteArraySegment(rc.Data);
        return rc.LinkLayerType switch {
            LinkLayers.Ethernet =>
                Ethernet(sp, new EthernetPacket(byteSegment)),
            _ => throw new NotSupportedException(
                "only Ethernet link layer is supported"
            ),
        };
    }

    /// <summary>
    /// Prints source and destination MAC address of Ethernet packet
    /// </summary>
    /// <param name="sp">Sniffed packet</param>
    /// <param name="packet">Ethernet packet</param>
    private SniffPacket? Ethernet(SniffPacket sp, EthernetPacket packet) {
        sp.SrcMac = BitConverter
            .ToString(packet.SourceHardwareAddress.GetAddressBytes())
            .Replace('-', ':');
        sp.DstMac = BitConverter
            .ToString(packet.DestinationHardwareAddress.GetAddressBytes())
            .Replace('-', ':');

        return HandleEth(sp, packet);
    }

    private SniffPacket? HandleEth(SniffPacket sp, EthernetPacket packet) {
        return packet.Type switch {
            EthernetType.IPv6 => HandleIP(sp, packet.Extract<IPPacket>()),
            _ => HandleDefault(sp, packet),
        };
    }

    private SniffPacket? HandleIP(SniffPacket sp, IPPacket packet) {
        sp.SrcIp = packet.SourceAddress;
        sp.DstIp = packet.DestinationAddress;

        return packet.Protocol switch {
            ProtocolType.IcmpV6 =>
                HandleIcmp6(sp, packet.Extract<IcmpV6Packet>()),
            _ => HandleDefaultIp(sp, packet),
        };
    }

    private SniffPacket? HandleIcmp6(SniffPacket sp, IcmpV6Packet packet) {
        switch (packet.Type) {
            /// MLD
            case IcmpV6Type.MulticastListenerQuery:
            case IcmpV6Type.MulticastListenerReport:
            case IcmpV6Type.MulticastListenerDone:
                if (!Args.IsFiltered(Filter.Mld))
                    return null;

                HandleDefaultIp(sp, packet);
                break;
            /// NDP
            case IcmpV6Type.RouterSolicitation:
            case IcmpV6Type.RouterAdvertisement:
            case IcmpV6Type.NeighborSolicitation:
            case IcmpV6Type.NeighborAdvertisement:
            case IcmpV6Type.RedirectMessage:
                if (!Args.IsFiltered(Filter.Ndp))
                    return null;

                HandleDefaultIp(sp, packet);
                break;
            default:
                break;
        }
        return sp;
    }

    private SniffPacket? HandleDefault(SniffPacket sp, Packet packet) {
        Ip(sp, packet);
        Port(sp, packet);
        sp.SetHexData(packet);
        return sp;
    }

    private SniffPacket? HandleDefaultIp(SniffPacket sp, Packet packet) {
        Port(sp, packet);
        sp.SetHexData(packet);
        return sp;
    }

    /// <summary>
    /// Sets IP of sniffed packet if available
    /// </summary>
    /// <param name="sp">Sniffed packet</param>
    /// <param name="packet">Packet</param>
    private void Ip(SniffPacket sp, Packet packet) {
        var ipPacket = packet.Extract<IPPacket>();
        if (ipPacket is not null) {
            sp.SrcIp = ipPacket.SourceAddress;
            sp.DstIp = ipPacket.DestinationAddress;
        }
    }

    /// <summary>
    /// Sets source and destination port of sniffed packet if possible
    /// </summary>
    /// <param name="sp">Sniffed packet</param>
    /// <param name="packet">Packet</param>
    private void Port(SniffPacket sp, Packet packet) {
        TcpPacket? tcpPacket;
        UdpPacket? udpPacket;
        if ((tcpPacket = packet.Extract<TcpPacket>()) is not null) {
            sp.SrcPort = tcpPacket.SourcePort;
            sp.DstPort = tcpPacket.DestinationPort;
        } else if ((udpPacket = packet.Extract<UdpPacket>()) is not null) {
            sp.SrcPort = udpPacket.SourcePort;
            sp.DstPort = udpPacket.DestinationPort;
        }
    }
}
