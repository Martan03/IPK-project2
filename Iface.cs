using SharpPcap;

/// <summary>
/// Class implementing functionality over interface
/// </summary>
public class Iface {
    private Sniffer sniffer { get; set; }
    private Args Args { get; set; }
    private ILiveDevice Dev {get; set;}
    private uint Recv { get; set; } = 0;

    /// <summary>
    /// Creates new Iface
    /// </summary>
    /// <param name="args"></param>
    public Iface(Args args) {
        sniffer = new(args);
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

    /// <summary>
    /// Packet arrival handler - prints packet information
    /// </summary>
    /// <param name="s">source of the event</param>
    /// <param name="e">captured packet</param>
    private void OnPacketArrival(object s, PacketCapture e) {
        if (Recv >= Args.Number)
            return;

        var rc = e.GetPacket();
        if (sniffer.Info(rc))
            Recv++;
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

    /// <summary>
    /// Gets filter string
    /// </summary>
    /// <returns>String containing the filter</returns>
    private string GetFilter() {
        List<string> filters = new();
        string ports = GetPorts();

        foreach (var filt in Args.Filters) {
            filters.Add(filt switch {
                Filter.Tcp => "tcp" + ports,
                Filter.Udp => "udp" + ports,
                Filter.Icmp4 => "icmp",
                Filter.Icmp6 or Filter.Ndp or Filter.Mld => "icmp6",
                Filter.Arp => "arp",
                Filter.Igmp => "igmp",
                _ => "",
            });
        }
        return string.Join(" or ", filters);
    }

    /// <summary>
    /// Gets port string for filter
    /// </summary>
    /// <returns>Port filter</returns>
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
