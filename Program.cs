namespace IPK_project1;

class Program
{
    static void Main(string[] argv) {
        Args args = new(argv);

        if (args.DisplayIfaces()) {
            Iface.ListIfaces();
        } else {
            Iface iface = new(args);
            iface.Sniff();
        }
    }
}
