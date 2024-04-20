using System.Text;
using System.Xml;
using PacketDotNet;
using PacketDotNet.Utils;
using SharpPcap;

public class SniffPacket {
    private Args Args { get; set; }

    public SniffPacket(Args args) {
        Args = args;
    }

    /// <summary>
    /// Prints info about the packet
    /// </summary>
    /// <param name="rc">RawCapture</param>
    public void Info(RawCapture rc) {
        Timestamp(rc);
        Console.WriteLine($"frame length: {rc.Data.Length} bytes");
        Mac(rc);
    /*
        var packet = Packet.ParsePacket(rc.LinkLayerType, rc.Data);
        Ip(packet);
        Port(packet);

        Console.WriteLine();
        HexData(packet);*/
    }

    /// <summary>
    /// Prints packet timestamp
    /// </summary>
    /// <param name="rc">RawCapture</param>
    private void Timestamp(RawCapture rc) {
        var time = rc.Timeval.Date;
        var t = XmlConvert.ToString(time, XmlDateTimeSerializationMode.Utc);
        Console.WriteLine($"timestamp: {t}");
    }

    /// <summary>
    /// Prints MAC address of packet if possible
    /// </summary>
    /// <param name="rc">RawCapture</param>
    private void Mac(RawCapture rc) {
        var byteSegment = new ByteArraySegment(rc.Data);
        switch (rc.LinkLayerType) {
            case LinkLayers.Ethernet:
                Ethernet(new EthernetPacket(byteSegment));
                break;
            case LinkLayers.LinuxSll:
                LinuxSll(new LinuxSllPacket(byteSegment));
                break;
            default:
                break;
        }
    }

    /// <summary>
    /// Prints source and destination IP if possible
    /// </summary>
    /// <param name="packet">Packet</param>
    private void Ip(Packet packet) {
        var ipPacket = packet.Extract<IPPacket>();
        if (ipPacket is not null) {
            Console.WriteLine(
                $"src IP: {ipPacket.SourceAddress}\n" +
                $"dst IP: {ipPacket.DestinationAddress}"
            );
        }
    }

    /// <summary>
    /// Prints source and destination port if possible
    /// </summary>
    /// <param name="packet">Packet</param>
    private void Port(Packet packet) {
        TcpPacket? tcpPacket;
        UdpPacket? udpPacket;
        if ((tcpPacket = packet.Extract<TcpPacket>()) is not null) {
            Console.WriteLine($"src port: {tcpPacket.SourcePort}");
            Console.WriteLine($"dst port: {tcpPacket.DestinationPort}");
        } else if ((udpPacket = packet.Extract<UdpPacket>()) is not null) {
            Console.WriteLine($"src port: {udpPacket.SourcePort}");
            Console.WriteLine($"dst port: {udpPacket.DestinationPort}");
        }
    }

    /// <summary>
    /// Prints hex data of the packet
    /// </summary>
    /// <param name="packet">Packet</param>
    private void HexData(Packet packet) {
        var bytes = packet.BytesSegment.Bytes;

        var sb = new StringBuilder();
        string text = "";
        string text2 = "";
        for (int i = 1; i <= bytes.Length; i++) {
            text = text + bytes[i - 1].ToString("x").PadLeft(2, '0') + " ";
            if (bytes[i - 1] >= 33 && bytes[i - 1] <= 126) {
                var b = new byte[1] { bytes[i - 1] };
                text2 += Encoding.ASCII.GetString(b);
            } else {
                text2 += ".";
            }

            if (i % 16 == 0) {
                string text3 = ((i - 16) / 16 * 10).ToString().PadLeft(4, '0');
                sb.AppendLine("0x" + text3 + ": " + text + " " + text2);
                text = "";
                text2 = "";
            } else if (i == bytes.Length) {
                string text3 =
                    (((i - 16) / 16 + 1) * 10).ToString().PadLeft(4, '0');
                sb.AppendLine(
                    "0x" + text3 + ": " + text.PadRight(49, ' ') + " " + text2
                );
            }
        }
        Console.WriteLine(sb);
    }

    /// <summary>
    /// Prints source and destination MAC address of Ethernet packet
    /// </summary>
    /// <param name="packet">Ethernet packet</param>
    private void Ethernet(EthernetPacket packet) {
        var srcMac = BitConverter
            .ToString(packet.SourceHardwareAddress.GetAddressBytes())
            .Replace('-', ':');
        var dstMac = BitConverter
            .ToString(packet.DestinationHardwareAddress.GetAddressBytes())
            .Replace('-', ':');
        Console.WriteLine(
            $"src MAC: {srcMac}\n" +
            $"dst MAC: {dstMac}"
        );

        HandleEth(packet);
    }

    /// <summary>
    /// Prints source MAC of LinuxSll packet
    /// </summary>
    /// <param name="packet">LinuxSll packet</param>
    private void LinuxSll(LinuxSllPacket packet) {
        var mac = BitConverter
            .ToString(packet.LinkLayerAddress)
            .Replace('-', ':');
        Console.WriteLine($"src MAC: {mac}");
    }

    private void HandleEth(EthernetPacket packet) {
        switch (packet.Type) {
            case EthernetType.IPv6:
                HandleIP(packet.Extract<IPPacket>());
                break;
            default:
                Ip(packet);
                Port(packet);
                break;
        }
    }

    private void HandleIP(IPPacket packet) {
        switch (packet.Protocol) {
            case ProtocolType.IcmpV6:
                HandleIcmp6(packet.Extract<IcmpV6Packet>());
                break;
            default:
                Ip(packet);
                Port(packet);
                break;
        }
    }

    private bool HandleIcmp6(IcmpV6Packet packet) {
        switch (packet.Type) {
            /// MLD
            case IcmpV6Type.MulticastListenerQuery:
            case IcmpV6Type.MulticastListenerReport:
            case IcmpV6Type.MulticastListenerDone:
                if (!Args.IsFiltered(Filter.Mld))
                    return false;

                Ip(packet);
                Port(packet);
                break;
            /// NDP
            case IcmpV6Type.RouterSolicitation:
            case IcmpV6Type.RouterAdvertisement:
            case IcmpV6Type.NeighborSolicitation:
            case IcmpV6Type.NeighborAdvertisement:
            case IcmpV6Type.RedirectMessage:
                if (!Args.IsFiltered(Filter.Ndp))
                    return false;

                Ip(packet);
                Port(packet);
                break;
            default:
                break;
        }
        return true;
    }
}
