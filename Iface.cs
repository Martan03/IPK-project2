using System.ComponentModel.DataAnnotations;
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
        Dev.Capture();
    }

    private void OnPacketArrival(object s, PacketCapture e) {
        var rc = e.GetPacket();
        var packet = Packet.ParsePacket(rc.LinkLayerType, rc.Data);

        Console.WriteLine(packet);

        var time = rc.Timeval.Date;
        var t = XmlConvert.ToString(time, XmlDateTimeSerializationMode.Utc);
        var srcMac =
            BitConverter.ToString(rc.Data, 6, 6).Replace("-", ":");
        var dstMac =
            BitConverter.ToString(rc.Data, 0, 6).Replace("-", ":");
        var len = e.Data.Length;

        ushort etherType = (ushort)((rc.Data[12] << 8) | rc.Data[13]);

        Console.WriteLine(
            $"timestamp: {t}\n" +
            $"src MAC: {srcMac}\n" +
            $"dst MAC: {dstMac}\n" +
            $"frame length: {len}"
        );
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
