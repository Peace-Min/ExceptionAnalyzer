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

                // 3) 수정 대상이 없으면 적용 없이 종료
                if (preview.Modified == 0)
                {
                    System.Windows.MessageBox.Show(
                        $"수정 대상이 없습니다. (수동검토 {preview.Skipped_NonTrivial}건)",
                        "미리보기 결과", MessageBoxButton.OK, MessageBoxImage.Information);
                    StatusText.Text = $"상태: 완료 - 수정 대상 없음 (수동검토 {preview.Skipped_NonTrivial}건)";
                    return;
                }

                if (!preview.IsComplete)
                {
                    global::Program.WriteFixReport(preview, apply: false);
                    System.Windows.MessageBox.Show(
                        "일부 프로젝트 또는 문서를 완전히 로드하지 못해 자동수정을 적용하지 않습니다.\n\nfix-report.txt의 WORKSPACE FAILURES와 수동 검토 목록을 먼저 확인하세요.",
                        "부분 분석 결과 - 적용 차단", MessageBoxButton.OK, MessageBoxImage.Warning);
                    StatusText.Text = "상태: 미리보기 완료 - 부분 분석이라 적용 차단";
                    return;
                }

                // 4) 안내된(informed) 확인 — 미리보기 수치 요약 + 되돌리기 경고
                var confirm = System.Windows.MessageBox.Show(
                    $"미리보기 결과:\n\n  수정 예정 catch : {preview.Modified}건\n  수동 검토      : {preview.Skipped_NonTrivial}건\n  완전도        : {(preview.IsComplete ? "Complete" : "PARTIAL — 일부 프로젝트/문서 누락")}\n\n위 미리보기(로그창) 내용대로 소스 파일을 직접 수정합니다.\n되돌리려면 git 등 버전관리가 필요합니다.\n\n적용할까요?",
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
                    StatusText.Text = $"상태: 완료 - catch {res.Modified}건 수정, 수동검토 {res.Skipped_NonTrivial}건, 되돌림 {res.CompileReverted}건 (fix-report.txt 생성)";
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
