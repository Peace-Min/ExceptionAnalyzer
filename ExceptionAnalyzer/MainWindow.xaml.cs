using System;
using System.IO;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Windows;
using WinForms = System.Windows.Forms;

namespace ExceptionAnalyzer
{
    public partial class MainWindow : Window
    {
        private string? _lastOutputDir;
        public MainWindow() { InitializeComponent(); }

        private void PickFolder_Click(object sender, RoutedEventArgs e)
        {
            using var dlg = new WinForms.OpenFileDialog
            {
                Title = "분석할 솔루션(.sln) 선택",
                Filter = "Visual Studio Solution (*.sln)|*.sln|All files (*.*)|*.*",
                CheckFileExists = true
            };
            if (dlg.ShowDialog() == WinForms.DialogResult.OK) PathBox.Text = dlg.FileName;
        }

        private async void Analyze_Click(object sender, RoutedEventArgs e)
        {
            var target = PathBox.Text?.Trim();
            if (string.IsNullOrEmpty(target) || (!Directory.Exists(target) && !File.Exists(target)))
            {
                StatusText.Text = "상태: 유효한 솔루션 파일 또는 폴더를 먼저 선택하세요.";
                return;
            }

            // 재진입 방지: 실행 중에는 분석/폴더선택 버튼을 비활성화(더블클릭 이중 적용 방지)
            AnalyzeButton.IsEnabled = false;
            PickFolderButton.IsEnabled = false;
            // 분석 로그를 로그창으로 라우팅 (finally 에서 콘솔로 복원)
            global::Program.Log = msg => Dispatcher.BeginInvoke(new Action(() =>
            {
                LogBox.AppendText(msg + Environment.NewLine);
                LogBox.ScrollToEnd();
            }));

            try
            {
                // 1) 미리보기 분석 (파일 미변경)
                LogBox.Clear();
                StatusText.Text = "상태: 미리보기 분석 중...";
                global::Program.FixResult preview;
                try
                {
                    preview = await Task.Run(() => global::Program.RunFix(target, apply: false));
                }
                catch (Exception ex)
                {
                    StatusText.Text = "상태: 오류 - " + ex.Message;
                    return;
                }

                // 2) 미리보기 결과를 로그창에 표시
                LogBox.AppendText(Environment.NewLine + "===== 미리보기 (아직 파일 미변경) =====" + Environment.NewLine);
                foreach (var b in preview.PreviewBlocks) LogBox.AppendText(b + Environment.NewLine);
                if (preview.ManualReview.Count > 0)
                {
                    LogBox.AppendText(Environment.NewLine + "수동 검토 필요:" + Environment.NewLine);
                    foreach (var m in preview.ManualReview) LogBox.AppendText("  " + m + Environment.NewLine);
                }
                LogBox.ScrollToEnd();

                // 3) 적용 대상(클린 파일)이 없으면 적용 없이 종료 (무결성 스킵 파일은 안내만)
                if (preview.Modified == 0)
                {
                    System.Windows.MessageBox.Show(
                        $"적용 대상(클린 파일)이 없습니다.\n\n  무결성 스킵 : {preview.SkippedIntegrityFiles}개 파일 (baseline 오류로 제외)\n  수동 검토   : {preview.Skipped_NonTrivial}건",
                        "미리보기 결과", MessageBoxButton.OK, MessageBoxImage.Information);
                    StatusText.Text = $"상태: 완료 - 적용 대상 없음 (무결성 스킵 {preview.SkippedIntegrityFiles}, 수동검토 {preview.Skipped_NonTrivial}건)";
                    return;
                }

                // 4) 안내된(informed) 확인 — 미리보기 수치 요약 + 스킵/되돌리기 경고
                //    파일별 best-effort: 클린 파일만 수정하고, baseline 오류 파일은 무결성 스킵으로 제외한다(하드 차단 없음).
                var confirm = System.Windows.MessageBox.Show(
                    $"미리보기 결과:\n\n  수정 예정 catch : {preview.Modified}건 (클린 파일)\n  무결성 스킵   : {preview.SkippedIntegrityFiles}개 파일 (baseline 오류로 제외)\n  수동 검토      : {preview.Skipped_NonTrivial}건\n  완전도        : {(preview.IsComplete ? "Complete" : "PARTIAL — 일부 파일 제외")}\n  커버리지 참고 : {preview.CoverageWarnings.Count}건 (비차단, fallback 보존)\n\n클린 파일만 소스에 직접 수정합니다(무결성 스킵 파일은 변경하지 않음).\n되돌리려면 git 등 버전관리가 필요합니다.\n\n적용할까요?",
                    "소스 자동수정 적용", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (confirm != MessageBoxResult.Yes)
                {
                    StatusText.Text = "상태: 미리보기만 수행(파일 미변경)";
                    return;
                }

                // 5) 적용 (소스 파일 직접 수정 + fix-report.txt 생성)
                StatusText.Text = "상태: 적용 중...";
                try
                {
                    var res = await Task.Run(() =>
                    {
                        var r = global::Program.RunFix(target, apply: true);
                        global::Program.WriteFixReport(r, true);
                        return r;
                    });

                    _lastOutputDir = AppDomain.CurrentDomain.BaseDirectory;

                    LogBox.AppendText(Environment.NewLine + "===== 소스 자동수정 결과 =====" + Environment.NewLine);
                    foreach (var b in res.PreviewBlocks) LogBox.AppendText(b + Environment.NewLine);
                    if (res.ManualReview.Count > 0)
                    {
                        LogBox.AppendText(Environment.NewLine + "수동 검토 필요:" + Environment.NewLine);
                        foreach (var m in res.ManualReview) LogBox.AppendText("  " + m + Environment.NewLine);
                    }
                    LogBox.ScrollToEnd();
                    if (res.ApplyFailed)
                        StatusText.Text = "상태: 오류 - 저장 실패(롤백 시도됨). fix-report 확인";
                    else
                        StatusText.Text = $"상태: 완료 - catch {res.Modified}건 수정, 무결성 스킵 {res.SkippedIntegrityFiles}개, 수동검토 {res.Skipped_NonTrivial}건, 되돌림 {res.CompileReverted}건 (fix-report.txt 생성)";
                }
                catch (Exception ex)
                {
                    StatusText.Text = "상태: 오류 - " + ex.Message;
                }
            }
            finally
            {
                global::Program.Log = Console.WriteLine;
                AnalyzeButton.IsEnabled = true;
                PickFolderButton.IsEnabled = true;
            }
        }

        private void OpenResult_Click(object sender, RoutedEventArgs e)
        {
            var dir = _lastOutputDir ?? AppDomain.CurrentDomain.BaseDirectory;
            try { Process.Start(new ProcessStartInfo("explorer.exe", dir) { UseShellExecute = true }); } catch { }
        }
    }
}
