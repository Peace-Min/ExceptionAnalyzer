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
            using var dlg = new WinForms.FolderBrowserDialog { Description = "분석할 프로젝트 폴더 선택" };
            if (dlg.ShowDialog() == WinForms.DialogResult.OK) PathBox.Text = dlg.SelectedPath;
        }

        private async void Analyze_Click(object sender, RoutedEventArgs e)
        {
            var target = PathBox.Text?.Trim();
            if (string.IsNullOrEmpty(target) || !Directory.Exists(target))
            { StatusText.Text = "상태: 유효한 폴더를 먼저 선택하세요."; return; }
            LogBox.Clear();
            StatusText.Text = "상태: 분석 중...";
            // 분석 로그를 TextBox로 라우팅 (UI 스레드로 마샬링)
            global::Program.Log = msg => Dispatcher.BeginInvoke(new Action(() => { LogBox.AppendText(msg + Environment.NewLine); LogBox.ScrollToEnd(); }));
            try
            {
                await Task.Run(() => global::Program.AnalyzeDirectory(target));
                _lastOutputDir = AppDomain.CurrentDomain.BaseDirectory;
                StatusText.Text = "상태: 완료. 결과 파일이 실행 폴더에 생성됨.";
            }
            catch (Exception ex) { StatusText.Text = "상태: 오류 - " + ex.Message; }
            finally { global::Program.Log = Console.WriteLine; }
        }

        private void OpenResult_Click(object sender, RoutedEventArgs e)
        {
            var dir = _lastOutputDir ?? AppDomain.CurrentDomain.BaseDirectory;
            try { Process.Start(new ProcessStartInfo("explorer.exe", dir) { UseShellExecute = true }); } catch { }
        }
    }
}
