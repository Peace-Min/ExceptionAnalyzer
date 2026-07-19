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
            if (e.Args.Length > 0 && e.Args[0] == "--selftest-fix")
            {
                int code = global::Program.RunSelfTestFix();
                Shutdown(code); return;
            }
            if (e.Args.Length >= 2 && e.Args[0] == "--fix")
            {
                bool apply = e.Args.Contains("--apply");
                bool sourceOnly = e.Args.Contains("--source-only");
                try
                {
                    global::Program.Log = Console.WriteLine;
                    var res = global::Program.RunFix(e.Args[1], apply, sourceOnly);
                    global::Program.WriteFixReport(res, apply);
                    Shutdown(0);
                }
                catch (Exception ex) { Console.WriteLine("FIX ERROR: " + ex); Shutdown(1); }
                return;
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
