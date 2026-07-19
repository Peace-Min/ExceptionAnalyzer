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

            var confirm = System.Windows.MessageBox.Show(
                $"대상: {target}\n\n과도한 catch(Exception)를 추론된 구체 예외 catch로 소스 파일에서 직접 수정합니다.\n\n되돌리려면 git 같은 버전 관리가 필요합니다. 백업을 권장합니다.\n\n계속할까요?",
                "소스 자동수정 적용", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (confirm != MessageBoxResult.Yes)
            {
                StatusText.Text = "상태: 취소됨";
                return;
            }

            LogBox.Clear();
            StatusText.Text = "상태: 분석 + 소스 수정 중...";
            global::Program.Log = msg => Dispatcher.BeginInvoke(new Action(() =>
            {
                LogBox.AppendText(msg + Environment.NewLine);
                LogBox.ScrollToEnd();
            }));

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
            finally
            {
                global::Program.Log = Console.WriteLine;
            }
        }

        private void OpenResult_Click(object sender, RoutedEventArgs e)
        {
            var dir = _lastOutputDir ?? AppDomain.CurrentDomain.BaseDirectory;
            try { Process.Start(new ProcessStartInfo("explorer.exe", dir) { UseShellExecute = true }); } catch { }
        }
    }
}
