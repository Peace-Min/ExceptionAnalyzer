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
                    global::Program.FixResult res;
                    if (apply)
                    {
                        var preview = global::Program.RunFix(e.Args[1], apply: false, sourceOnly);
                        if (!preview.IsComplete)
                        {
                            global::Program.WriteFixReport(preview, apply: false);
                            Console.WriteLine("FIX BLOCKED: 무결성 문제(워크스페이스/baseline/문서 누락 등)로 --apply를 수행하지 않습니다. fix-report.txt의 INTEGRITY FAILURES와 MANUAL REVIEW를 먼저 확인하세요.");
                            Shutdown(2);
                            return;
                        }
                    }

                    res = global::Program.RunFix(e.Args[1], apply, sourceOnly);
                    global::Program.WriteFixReport(res, apply);
                    // 권고2: 저장 실패는 성공이 아닌 실패로 보고(exit 1). 부분 수행(무결성)은 exit 2.
                    if (res.ApplyFailed)
                        Console.WriteLine("FIX APPLY FAILED: 파일 저장에 실패했습니다(롤백 시도됨). fix-report.txt를 확인하세요.");
                    Shutdown(res.ApplyFailed ? 1 : (res.IsComplete ? 0 : 2));
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
