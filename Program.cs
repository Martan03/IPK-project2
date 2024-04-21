namespace IPK_project1;

class Program
{
    static void Main(string[] argv) {
        try {
            Run(argv);
        } catch (Exception e) {
            Console.Error.WriteLine($"Error: {e}");
        }
    }

    static void Run(string[] argv) {
        Args args = new(argv);

        if (args.DisplayIfaces()) {
            Iface.ListIfaces();
        } else {
            Iface iface = new(args);
            iface.Sniff();
        }
    }
}
