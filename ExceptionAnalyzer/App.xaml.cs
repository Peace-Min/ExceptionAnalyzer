using System;
using System.Linq;
using System.Windows;

namespace ExceptionAnalyzer
{
    public partial class App : System.Windows.Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            if (e.Args.Length > 0 && (e.Args[0] == "--selftest" || e.Args[0] == "--selftest-xml"))
            {
                int code = global::Program.RunSelfTestHeadless(e.Args[0]);
                Shutdown(code); return;
            }
            if (e.Args.Length >= 2 && e.Args[0] == "--analyze")
            {
                try { global::Program.Log = Console.WriteLine; global::Program.AnalyzeDirectory(e.Args[1]); Shutdown(0); }
                catch (Exception ex) { Console.WriteLine("ANALYZE ERROR: " + ex); Shutdown(1); }
                return;
            }
            new MainWindow().Show();
        }
    }
}
