using System.ComponentModel.DataAnnotations;
using System.Net.NetworkInformation;
using System.Text;
using System.Xml;
using PacketDotNet;
using SharpPcap;

/// <summary>
/// Class implementing functionality over interface
/// </summary>
public class Iface {
    private Args Args { get; set; }
    private ILiveDevice Dev {get; set;}
    private uint Recv { get; set; } = 0;

    /// <summary>
    /// Creates new Iface
    /// </summary>
    /// <param name="args"></param>
    public Iface(Args args) {
        Args = args;
        Dev = GetIface(args.Interface!);
    }

    /// <summary>
    /// Lists available interfaces
    /// </summary>
    public static void ListIfaces() {
        var devices = CaptureDeviceList.Instance;
        foreach (var dev in devices)
            Console.WriteLine($"{dev.Name}");
    }

    /// <summary>
    /// Starts sniffing for packets
    /// </summary>
    public void Sniff() {
        Dev.Open(DeviceModes.Promiscuous);
        var filter = GetFilter();
        if (filter.Length > 0)
            Dev.Filter = filter;

        Dev.OnPacketArrival += OnPacketArrival;
        Dev.StartCapture();

        while (Recv < Args.Number) {}

        Dev.StopCapture();
        Dev.Close();
    }

    private void OnPacketArrival(object s, PacketCapture e) {
        Recv++;
        var rc = e.GetPacket();
        var packet = Packet.ParsePacket(rc.LinkLayerType, rc.Data);
        Console.WriteLine(packet);

        var ethPacket = packet.Extract<EthernetPacket>();
        var ipPacket = packet.Extract<IPPacket>();
        var tcpPacket = packet.Extract<TcpPacket>();
        var udpPacket = packet.Extract<UdpPacket>();

        var time = rc.Timeval.Date;
        var t = XmlConvert.ToString(time, XmlDateTimeSerializationMode.Utc);

        var srcMac = BitConverter
            .ToString(rc.Data.Take(6).ToArray())
            .Replace("-", ":");
        var dstMac = BitConverter
            .ToString(rc.Data.Skip(6).Take(6).ToArray())
            .Replace("-", ":");

        Console.WriteLine(
            $"timestamp: {t}\n" +
            $"src MAC: {srcMac}\n" +
            $"dst MAC: {dstMac}\n" +
            $"frame length: {rc.Data.Length} bytes\n" +
            $"src IP: {ipPacket?.SourceAddress}\n" +
            $"dst IP: {ipPacket?.DestinationAddress}"
        );

        if (tcpPacket is not null) {
            Console.WriteLine($"src port: {tcpPacket.SourcePort}");
            Console.WriteLine($"dst port: {tcpPacket.DestinationPort}");
        } else if (udpPacket is not null) {
            Console.WriteLine($"src port: {udpPacket.SourcePort}");
            Console.WriteLine($"dst port: {udpPacket.DestinationPort}");
        }
        Console.WriteLine();

        Console.WriteLine(GetDataHex(packet.BytesSegment.Bytes));
    }

    private string GetDataHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
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
        return sb.ToString();
    }

    /// <summary>
    /// Gets interface by its name
    /// </summary>
    /// <param name="name">name of the interface to get</param>
    /// <returns>Found interface</returns>
    /// <exception cref="ArgumentException">Interface wasn't found</exception>
    private static ILiveDevice GetIface(string name) {
        var devices = CaptureDeviceList.Instance;
        foreach (var dev in devices) {
            if (dev.Name == name)
                return dev;
        }

        throw new ArgumentException($"interface '{name}' not found");
    }

    private string GetFilter() {
        List<string> filters = new();
        string ports = GetPorts();

        foreach (var filt in Args.Filters) {
            filters.Add(filt switch {
                Filter.Tcp => "tcp" + ports,
                Filter.Udp => "udp" + ports,
                Filter.Icmp4 => "icmp",
                Filter.Icmp6 => "icmp6",
                Filter.Arp => "arp",
                // TODO
                Filter.Ndp => "icmp6",
                Filter.Igmp => "igmp",
                // TODO
                Filter.Mld => "icmp6",
                _ => throw new NotImplementedException(),
            });
        }
        return string.Join(" or ", filters);
    }

    private string GetPorts() {
        string ports = "";
        if (Args.DstPort is not null) {
            ports += $" and dst port {Args.DstPort}";
        }
        if (Args.SrcPort is not null) {
            ports += $" and src port {Args.SrcPort}";
        }
        return ports;
    }
}
