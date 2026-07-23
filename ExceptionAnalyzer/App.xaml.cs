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
                    // 파일별 best-effort: 사전 preview 게이트를 제거 — apply 는 곧장 진행하고, 클린 파일만 적용된다.
                    var res = global::Program.RunFix(e.Args[1], apply, sourceOnly);
                    global::Program.WriteFixReport(res, apply);
                    // 권고2: 저장 실패는 성공이 아닌 실패로 보고(exit 1). 부분 수행(무결성)은 exit 2(클린 파일은 적용됨).
                    if (res.ApplyFailed)
                        Console.WriteLine("FIX APPLY FAILED: 파일 저장에 실패했습니다(롤백 시도됨). fix-report.txt를 확인하세요.");
                    else if (apply && !res.IsComplete)
                        Console.WriteLine($"부분 적용: {res.AppliedFileCount}개 파일 적용, {res.SkippedIntegrityFiles}개 파일 무결성 스킵(baseline 오류). fix-report.txt 확인.");
                    Shutdown(res.ApplyFailed ? 1 : (res.IsComplete ? 0 : 2));
                }
                catch (Exception ex) { Console.WriteLine("FIX ERROR: " + ex); Shutdown(1); }
                return;
            }
            if (e.Args.Length >= 2 && e.Args[0] == "--analyze")
            {
                try
                {
                    global::Program.Log = Console.WriteLine;
                    // FIX 4: --fix 처럼 부분 로드를 exit code 로 신호(완전=0, 부분=2, 예외=1).
                    bool complete = global::Program.AnalyzeDirectory(e.Args[1]);
                    if (!complete)
                        Console.WriteLine("분석 부분 완료: 일부 프로젝트/문서 로드 실패");
                    Shutdown(complete ? 0 : 2);
                }
                catch (Exception ex) { Console.WriteLine("ANALYZE ERROR: " + ex); Shutdown(1); }
                return;
            }
            new MainWindow().Show();
        }
    }
}
