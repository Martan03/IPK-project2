using System.Net;
using System.Text;
using System.Xml;
using PacketDotNet;

public class SniffPacket {
    public string Timestamp { get; set; }
    public int FrameLen { get; set; }
    public string? SrcMac { get; set; }
    public string? DstMac { get; set; }
    public IPAddress? SrcIp { get; set; }
    public IPAddress? DstIp { get; set; }
    public ushort? SrcPort { get; set; }
    public ushort? DstPort { get; set; }
    public string HexData { get; set; } = "";

    public SniffPacket(DateTime timestamp, int frameLen) {
        Timestamp = ConvTimestamp(timestamp);
        FrameLen = frameLen;
    }

    public override string ToString() {
        var res = $"timestamp: {Timestamp}\n";

        if (SrcMac is not null)
            res += $"src MAC: {SrcMac}\n";
        if (DstMac is not null)
            res += $"dst MAC: {DstMac}\n";

        res += $"frame length: {FrameLen} bytes\n";

        if (SrcIp is not null)
            res += $"src IP: {SrcIp}\n";
        if (DstIp is not null)
            res += $"dst IP: {DstIp}\n";

        if (SrcPort is not null)
            res += $"src IP: {SrcPort}\n";
        if (DstPort is not null)
            res += $"dst IP: {DstPort}\n";

        res += $"\n{HexData}";
        return res;
    }

    /// <summary>
    /// Sets hex data of the sniffed packet
    /// </summary>
    /// <param name="packet">Packet</param>
    public void SetHexData(Packet packet) {
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
        HexData = sb.ToString();
    }

    /// <summary>
    /// Converts datetime to its string representation
    /// </summary>
    /// <param name="datetime">Datime to convert</param>
    /// <returns>String representation</returns>
    private static string ConvTimestamp(DateTime datetime) {
        return XmlConvert.ToString(datetime, XmlDateTimeSerializationMode.Utc);
    }
}
