using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.MSBuild;
using Microsoft.Build.Locator;
using System.Xml.Linq;
using System;
using System.IO;
using System.Linq;
using Microsoft.CodeQuality.Analyzers.ApiDesignGuidelines;
using System.Reflection;
using System.Text;


public class ApiDocumentation
{
    public string MethodName { get; set; }
    public string Summary { get; set; }
    public Dictionary<string, string> Exceptions { get; set; } = new Dictionary<string, string>();
}


internal partial class Program
{
    private static Dictionary<string, string> methodExceptionList = new Dictionary<string, string>();
    private static readonly string NET_FRAMEWORK_PATH = @"C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.7.2\ko";
    private static Dictionary<string, ApiDocumentation> _apiDocCache = new Dictionary<string, ApiDocumentation>();
    private static bool _msBuildRegistered;
    private static bool _codePagesRegistered;

    // 분석 로그 싱크: 콘솔(헤드리스) 또는 WPF 창으로 라우팅
    public static Action<string> Log = Console.WriteLine;

    private static void EnsureMSBuildRegistered()
    {
        if (_msBuildRegistered || MSBuildLocator.IsRegistered)
        {
            _msBuildRegistered = true;
            return;
        }

        try
        {
            MSBuildLocator.RegisterDefaults();
        }
        catch (InvalidOperationException)
        {
            var sdkPath = FindDotNetSdkMsBuildPath();
            if (sdkPath == null)
            {
                throw;
            }

            MSBuildLocator.RegisterMSBuildPath(sdkPath);
        }

        _msBuildRegistered = true;
    }

    private static string? FindDotNetSdkMsBuildPath()
    {
        var roots = new[]
        {
            Environment.GetEnvironmentVariable("DOTNET_ROOT"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "dotnet")
        };

        foreach (var root in roots.Where(r => !string.IsNullOrWhiteSpace(r)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var sdkRoot = Path.Combine(root!, "sdk");
            if (!Directory.Exists(sdkRoot))
            {
                continue;
            }

            var sdkPath = Directory.GetDirectories(sdkRoot)
                .Select(d => new { Path = d, Version = ParseSdkVersion(Path.GetFileName(d)) })
                .Where(x => x.Version != null
                    && x.Version.Major <= Environment.Version.Major
                    && File.Exists(Path.Combine(x.Path, "MSBuild.dll")))
                .OrderByDescending(x => x.Version)
                .Select(x => x.Path)
                .FirstOrDefault();

            if (sdkPath != null)
            {
                return sdkPath;
            }
        }

        return null;
    }

    private static Version? ParseSdkVersion(string name)
    {
        var numeric = new string(name.TakeWhile(c => char.IsDigit(c) || c == '.').ToArray()).TrimEnd('.');
        return Version.TryParse(numeric, out var version) ? version : null;
    }

    // A directory is a solution root only when it contains exactly one solution.
    // Requiring an explicit .sln for ambiguous roots prevents silently analyzing
    // a different project than the user selected.
    private static string ResolveSolutionPath(string target)
    {
        if (File.Exists(target) && string.Equals(Path.GetExtension(target), ".sln", StringComparison.OrdinalIgnoreCase))
            return Path.GetFullPath(target);

        if (!Directory.Exists(target))
            throw new DirectoryNotFoundException($"분석 대상이 존재하지 않습니다: {target}");

        var solutions = Directory.GetFiles(target, "*.sln", SearchOption.TopDirectoryOnly);
        if (solutions.Length == 1) return Path.GetFullPath(solutions[0]);
        if (solutions.Length == 0)
            throw new InvalidOperationException($"선택한 폴더에 .sln 파일이 없습니다: {target}");
        throw new InvalidOperationException($"선택한 폴더에 .sln 파일이 여러 개입니다. 분석할 .sln을 직접 선택하세요: {target}");
    }

    private static string? TryResolveSingleSolutionPath(string target)
    {
        if (File.Exists(target) && string.Equals(Path.GetExtension(target), ".sln", StringComparison.OrdinalIgnoreCase))
            return Path.GetFullPath(target);

        if (!Directory.Exists(target))
            return null;

        var solutions = Directory.GetFiles(target, "*.sln", SearchOption.TopDirectoryOnly);
        return solutions.Length == 1 ? Path.GetFullPath(solutions[0]) : null;
    }

    private static MSBuildWorkspace OpenSolutionWorkspace(string target, out string solutionPath, Action<string>? onFailure = null)
    {
        EnsureMSBuildRegistered();
        solutionPath = ResolveSolutionPath(target);
        var workspace = MSBuildWorkspace.Create();
        workspace.WorkspaceFailed += (_, e) =>
        {
            Log($"⚠️ MSBuildWorkspace: {e.Diagnostic.Message}");
            // P1-11: 로드 실패는 완전성(completeness) 판정을 위해 수집한다 (경고는 무시).
            if (e.Diagnostic.Kind == WorkspaceDiagnosticKind.Failure) onFailure?.Invoke(e.Diagnostic.Message);
        };
        return workspace;
    }

    private static void ReportSkipped(StreamWriter? writer, string message)
    {
        var text = "⚠️ 건너뜀: " + message;
        if (writer != null) writer.WriteLine(text);
        Log(text);
    }

    // CP949(EUC-KR) 등 코드페이지 인코딩 사용을 위해 provider 를 1회만 등록 (net6/net8 in-box 아님).
    private static void EnsureCodePagesRegistered()
    {
        if (_codePagesRegistered) return;
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        _codePagesRegistered = true;
    }

    // FIX 5: obj/bin/.git 및 생성 파일(.g.cs/.Designer.cs 등)은 수정·분석 대상에서 제외.
    private static bool IsExcludedSourcePath(string path)
    {
        var norm = path.Replace('/', '\\');
        foreach (var seg in new[] { "\\obj\\", "\\bin\\", "\\.git\\" })
            if (norm.Contains(seg, StringComparison.OrdinalIgnoreCase)) return true;
        var name = Path.GetFileName(norm);
        if (name.EndsWith(".g.cs", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".g.i.cs", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".Designer.cs", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".generated.cs", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("TemporaryGeneratedFile_", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    // FIX 4: BOM/코드페이지/EOL 을 감지해 원본 그대로 되쓰기 위한 (text, encoding, eol) 반환.
    private static (string text, Encoding encoding, string eol) ReadSourcePreserving(string file)
    {
        var bytes = File.ReadAllBytes(file);
        Encoding enc;
        string text;
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        { enc = new UTF8Encoding(true); text = enc.GetString(bytes, 3, bytes.Length - 3); }
        else if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
        { enc = new UnicodeEncoding(false, true); text = Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2); }
        else if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
        { enc = new UnicodeEncoding(true, true); text = Encoding.BigEndianUnicode.GetString(bytes, 2, bytes.Length - 2); }
        else
        {
            try { text = new UTF8Encoding(false, true).GetString(bytes); enc = new UTF8Encoding(false); }
            catch (DecoderFallbackException)
            {
                EnsureCodePagesRegistered();
                var cp949 = Encoding.GetEncoding(949); // requires CodePagesEncodingProvider registration
                text = cp949.GetString(bytes); enc = cp949;
            }
        }
        var eol = text.Contains("\r\n") ? "\r\n" : "\n";
        return (text, enc, eol);
    }
}
