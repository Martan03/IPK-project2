using SharpPcap;

namespace IPK_project1;

class Program
{
    static void Main(string[] argv) {
        Args args = new(argv);

        if (args.DisplayIfaces()) {
            DisplayIfaces();
        }
    }

    /// <summary>
    /// Displays interfaces
    /// </summary>
    static void DisplayIfaces() {
        var devices = CaptureDeviceList.Instance;
        foreach (var dev in devices)
            Console.WriteLine($"{dev.Name}");
    }
}
