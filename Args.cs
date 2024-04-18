/// <summary>
/// Class parsing input arguments
/// </summary>
public class Args {
    public string? Interface { get; set; }
    public List<Filter> Filters { get; set; } = new();
    public ushort? DstPort { get; set; } = null;
    public ushort? SrcPort { get; set; } = null;
    public uint Number { get; set; } = 1;

    /// <summary>
    /// Parses args
    /// </summary>
    /// <param name="args">args to be parsed</param>
    public Args(ReadOnlySpan<string> args) {
        int len = args.Length;
        bool port = false;

        while (!args.IsEmpty) {
            switch (args[0]) {
                case "-i" or "--interface":
                    try {
                        args = GetNext(args);
                    } catch (ArgumentException) {
                        if (len != 1) {
                            throw new ArgumentException(
                                "interface must be specified"
                            );
                        }
                        return;
                    }
                    Interface = args[0];
                    break;
                case "-t" or "--tcp":
                    Filters.Add(Filter.Tcp);
                    port = true;
                    break;
                case "-u" or "--udp":
                    Filters.Add(Filter.Udp);
                    port = true;
                    break;
                case "-p":
                    args = GetNext(args);
                    DstPort = ParseArg<ushort>(args[0]);
                    SrcPort = DstPort;
                    break;
                case "--port-source":
                    args = GetNext(args);
                    SrcPort = ParseArg<ushort>(args[0]);
                    break;
                case "--port-destination":
                    args = GetNext(args);
                    DstPort = ParseArg<ushort>(args[0]);
                    break;
                case "--icmp4":
                    Filters.Add(Filter.Icmp4);
                    break;
                case "--icmp6":
                    Filters.Add(Filter.Icmp6);
                    break;
                case "--arp":
                    Filters.Add(Filter.Arp);
                    break;
                case "--ndp":
                    Filters.Add(Filter.Ndp);
                    break;
                case "--igmp":
                    Filters.Add(Filter.Igmp);
                    break;
                case "--mld":
                    Filters.Add(Filter.Mld);
                    break;
                case "-n":
                    args = GetNext(args);
                    Number = ParseArg<uint>(args[0]);
                    break;
                default:
                    throw new ArgumentException(
                        $"unknown argument '{args[0]}'"
                    );
            }
            args = args[1..];
        }

        if ((DstPort is not null || SrcPort is not null) && !port)
            throw new ArgumentException();
    }

    /// <summary>
    /// Check whether interfaces should be displayed
    /// </summary>
    /// <returns>true when should display, else false</returns>
    public bool DisplayIfaces() {
        return Interface is null && SrcPort is null &&
            DstPort is null && !Filters.Any();
    }

    /// <summary>
    /// Move span to next argument
    /// </summary>
    /// <param name="args">Span with arguments</param>
    /// <returns>Moved span to next argument</returns>
    /// <exception cref="Exception">When no next argument</exception>
    private ReadOnlySpan<string> GetNext(ReadOnlySpan<string> args) {
        string flag = args[0];
        args = args[1..];
        if (args.IsEmpty) {
            throw new ArgumentException(
                $"Flag '{flag}' expects value after it"
            );
        }

        return args;
    }

    /// <summary>
    /// Parses given argument
    /// </summary>
    /// <typeparam name="T">Type of the argument to parse to</typeparam>
    /// <param name="arg">Argument to be parsed</param>
    /// <returns>Parsed argument</returns>
    /// <exception cref="ArgumentException">Error parsing</exception>
    private T ParseArg<T>(string arg) where T: IParsable<T> {
        if (T.TryParse(arg, null, out T? value)) {
            return value;
        }
        throw new ArgumentException("Invalid argument type");
    }
}