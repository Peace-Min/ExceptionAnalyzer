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


internal class Program
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

    private static void LoadXmlDocumentation()
    {
        string[] xmlFiles;
        try
        {
            xmlFiles = Directory.GetFiles(NET_FRAMEWORK_PATH, "*.xml");
        }
        catch (Exception ex)
        {
            // P1-10: 하드코딩 경로가 없어도 크래시 없이 심볼 기반 조회(GetDocumentationCommentXml)로 대체.
            Log($"⚠️ 기본 XML 문서 경로 없음 — 심볼 기반 조회로 대체: {NET_FRAMEWORK_PATH} ({ex.Message})");
            return;
        }

        foreach (var xmlFile in xmlFiles)
        {
            try
            {
                var doc = XDocument.Load(xmlFile);
                var members = doc.Root?.Element("members")?.Elements("member") ?? Enumerable.Empty<XElement>();

                foreach (var member in members)
                {
                    var nameAttr = member.Attribute("name")?.Value;
                    // P1-6: 속성(P:)도 포함해 문서화된 예외 조회 대상에 넣는다.
                    if (string.IsNullOrEmpty(nameAttr) || !(nameAttr.StartsWith("M:") || nameAttr.StartsWith("P:"))) continue;

                    var apiDoc = new ApiDocumentation
                    {
                        MethodName = nameAttr, // 전체 메타데이터 ID를 키로 사용
                        Summary = member.Element("summary")?.Value.Trim(),
                    };

                    var exceptions = member.Elements("exception");
                    foreach (var exception in exceptions)
                    {
                        var exceptionType = exception.Attribute("cref")?.Value;
                        if (string.IsNullOrEmpty(exceptionType)) continue;

                        exceptionType = exceptionType.StartsWith("T:") ? exceptionType.Substring(2) : exceptionType;
                        var description = exception.Value.Trim();
                        apiDoc.Exceptions[exceptionType] = description;
                    }

                    _apiDocCache[nameAttr] = apiDoc; // 원본 메타데이터 ID를 그대로 사용
                }
            }
            catch (Exception ex)
            {
                Log($"XML 문서 로드 중 오류 발생: {xmlFile}");
                Log(ex.Message);
            }
        }
    }

    // P1-10: 1차 사전 로드된 v4.7.2/ko 캐시(한글 설명). 2차 심볼의 실제 참조 문서(GetDocumentationCommentXml)
    // — 대상 TFM/NuGet 문서를 반영. 반환 null = 문서화된 예외 없음.
    private static Dictionary<string, string>? LookupDocumentedExceptions(ISymbol symbol)
    {
        var docId = symbol.GetDocumentationCommentId();

        // 1차: ko 캐시 (한글 설명 우선)
        if (docId != null && _apiDocCache.TryGetValue(docId, out var cached))
            return cached.Exceptions.Count > 0 ? cached.Exceptions : null;

        // 2차: 심볼이 참조하는 실제 XML 문서 (대상 TFM/NuGet)
        string? xml;
        try { xml = symbol.GetDocumentationCommentXml(expandIncludes: true); }
        catch { xml = null; }
        if (string.IsNullOrWhiteSpace(xml)) return null;

        try
        {
            // 반환 xml 은 <member ...> 프래그먼트 — 루트로 파싱해 <exception cref="T:..."> 수집
            var root = XElement.Parse(xml);
            var dict = new Dictionary<string, string>();
            foreach (var ex in root.Elements("exception"))
            {
                var cref = ex.Attribute("cref")?.Value;
                if (string.IsNullOrEmpty(cref)) continue;
                var key = cref.StartsWith("T:") ? cref.Substring(2) : cref;
                dict[key] = ex.Value.Trim();
            }

            // 재파싱 방지를 위해 캐시에 적재
            if (docId != null)
                _apiDocCache[docId] = new ApiDocumentation { MethodName = docId, Summary = string.Empty, Exceptions = dict };

            return dict.Count > 0 ? dict : null;
        }
        catch
        {
            return null; // 손상된 문서 프래그먼트 방어
        }
    }

    // P1-6/P1-7: try 스코프에서 '실행 시 예외를 던질 수 있는' 노드 수집.
    // 경계: 람다/무명함수/로컬함수 본문은 정의만으로 실행되지 않으므로 하강 금지.
    // 중첩 try 의 보호 블록은 내부 catch 가 처리하므로 제외하되, 그 catch/finally 본문은 밖으로 전파되므로 포함.
    private static void CollectThrowCapable(SyntaxNode node,
        List<InvocationExpressionSyntax> invocations,
        List<BaseObjectCreationExpressionSyntax> creations,
        List<ExpressionSyntax> thrownExpressions,
        List<ExpressionSyntax> accessExpressions)
    {
        foreach (var child in node.ChildNodes())
        {
            switch (child)
            {
                case AnonymousFunctionExpressionSyntax:
                case LocalFunctionStatementSyntax:
                    continue;
                case TryStatementSyntax nested:
                    foreach (var c in nested.Catches) CollectThrowCapable(c.Block, invocations, creations, thrownExpressions, accessExpressions);
                    if (nested.Finally != null) CollectThrowCapable(nested.Finally.Block, invocations, creations, thrownExpressions, accessExpressions);
                    continue;
                case InvocationExpressionSyntax inv:
                    invocations.Add(inv); CollectThrowCapable(inv, invocations, creations, thrownExpressions, accessExpressions); continue;
                case BaseObjectCreationExpressionSyntax oc:
                    creations.Add(oc); CollectThrowCapable(oc, invocations, creations, thrownExpressions, accessExpressions); continue;
                case ThrowStatementSyntax ts:
                    if (ts.Expression != null) thrownExpressions.Add(ts.Expression);
                    CollectThrowCapable(ts, invocations, creations, thrownExpressions, accessExpressions); continue;
                case ThrowExpressionSyntax te:
                    thrownExpressions.Add(te.Expression); CollectThrowCapable(te, invocations, creations, thrownExpressions, accessExpressions); continue;
                case MemberAccessExpressionSyntax:
                case ElementAccessExpressionSyntax:
                    // 속성/인덱서 후보 — 하강은 계속(내부 호출/생성 놓치지 않도록)
                    accessExpressions.Add((ExpressionSyntax)child);
                    CollectThrowCapable(child, invocations, creations, thrownExpressions, accessExpressions); continue;
                default:
                    CollectThrowCapable(child, invocations, creations, thrownExpressions, accessExpressions); continue;
            }
        }
    }

    // P1-6: 생성자 호출의 문서화된 예외를 집계. 비프레임워크 생성자는 보고만(생성자 선언은 재귀 분석 대상 아님).
    private static void CollectFrameworkCreationExceptions(List<BaseObjectCreationExpressionSyntax> creations, SemanticModel semanticModel, Dictionary<string, string> exMap, StreamWriter? writer)
    {
        foreach (var oc in creations)
        {
            var ctorSymbol = semanticModel.GetSymbolInfo(oc).Symbol as IMethodSymbol;
            if (ctorSymbol == null) continue;

            var ns = ctorSymbol.ContainingNamespace?.ToDisplayString();
            if (string.IsNullOrEmpty(ns)) continue;

            if (ns.StartsWith("System") || ns.StartsWith("Microsoft"))
            {
                var docExceptions = LookupDocumentedExceptions(ctorSymbol);
                if (docExceptions == null) continue;
                foreach (var exception in docExceptions)
                {
                    exMap[exception.Key] = exception.Value;
                    if (writer != null)
                    {
                        writer.WriteLine($"        → 예상 예외(생성자): {exception.Key}");
                        Log($"        → 예상 예외(생성자): {exception.Key}");
                    }
                }
            }
            else if (writer != null)
            {
                var msg = $"프레임워크에 등록되지 않은 API : {ctorSymbol.ContainingNamespace}.{ctorSymbol.ContainingType.Name}.{ctorSymbol.Name}";
                writer.WriteLine($"    🔧 {msg}(생성자)");
                Log($"    🔧 {msg}(생성자)");
            }
        }
    }

    // P1-6: try 내부에서 직접 throw 된 예외의 정적 타입을 집계.
    private static void CollectThrownExpressionTypes(List<ExpressionSyntax> thrownExpressions, SemanticModel semanticModel, Dictionary<string, string> exMap, StreamWriter? writer)
    {
        foreach (var expr in thrownExpressions)
        {
            var type = semanticModel.GetTypeInfo(expr).Type;
            if (type == null) continue; // 미해석 타입은 조용히 스킵
            exMap[type.ToDisplayString()] = "직접 throw된 예외";
            if (writer != null)
            {
                writer.WriteLine($"        → 직접 throw: {type}");
                Log($"        → 직접 throw: {type}");
            }
        }
    }

    // P1-6: 프레임워크 속성/인덱서 접근의 문서화된 예외를 집계.
    // 메서드/필드 접근(예: a.B())은 IPropertySymbol 필터로 자연 제외된다.
    private static void CollectPropertyAccessExceptions(List<ExpressionSyntax> accessExpressions, SemanticModel semanticModel, Dictionary<string, string> exMap, StreamWriter? writer)
    {
        foreach (var access in accessExpressions)
        {
            var propSymbol = semanticModel.GetSymbolInfo(access).Symbol as IPropertySymbol;
            if (propSymbol == null) continue;

            var ns = propSymbol.ContainingNamespace?.ToDisplayString();
            if (string.IsNullOrEmpty(ns)) continue;
            if (!(ns.StartsWith("System") || ns.StartsWith("Microsoft"))) continue;

            var docExceptions = LookupDocumentedExceptions(propSymbol);
            if (docExceptions == null) continue;
            foreach (var exception in docExceptions)
            {
                exMap[exception.Key] = exception.Value;
                if (writer != null)
                {
                    writer.WriteLine($"        → 예상 예외(속성): {exception.Key}");
                    Log($"        → 예상 예외(속성): {exception.Key}");
                }
            }
        }
    }

    // 분석 진입점: 하드코딩 경로 대신 인자로 받은 폴더를 분석한다. 백그라운드 스레드에서 반복 호출해도 안전.
    public static void AnalyzeDirectory(string targetDirectory)
    {
        // 반복 호출 안전: 파일별 예외 목록 상태 초기화
        methodExceptionList = new Dictionary<string, string>();
        EnsureCodePagesRegistered();

        // XML 문서 로드 (최초 1회)
        if (_apiDocCache.Count == 0)
        {
            Log("📚 .NET Framework XML 문서 로딩 중...");
            LoadXmlDocumentation();
            Log($"✅ {_apiDocCache.Count}개의 API 문서 로드 완료");
        }

        using var workspace = OpenSolutionWorkspace(targetDirectory, out var solutionPath);
        var solution = workspace.OpenSolutionAsync(solutionPath).GetAwaiter().GetResult();
        var lastFolderName = Path.GetFileNameWithoutExtension(solutionPath);

        // 2. 출력 파일 경로 지정
        var outputPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"{lastFolderName}_ApiCallCandidates.txt");
        var unregisteredExceptionMapPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"{lastFolderName}_UnregisteredExceptionMap.txt"); // ExceptionMap에 등록안된 메소드만 별도로 저장

        // 3. 출력 스트림 오픈
        using var writer = new StreamWriter(outputPath);
        using var exceptionWriter = new StreamWriter(unregisteredExceptionMapPath);

        Log($"🔍 솔루션 분석 시작: {solutionPath}");

        foreach (var project in solution.Projects.Where(p => p.Language == LanguageNames.CSharp))
        {
            var compilation = project.GetCompilationAsync().GetAwaiter().GetResult() as CSharpCompilation;
            if (compilation == null)
            {
                ReportSkipped(writer, $"프로젝트 컴파일을 만들 수 없음: {project.Name}");
                continue;
            }

            foreach (var document in project.Documents)
            {
                // FIX 5: obj/bin/.git·생성 파일 제외 (분석 일관성 유지)
                if (document.FilePath != null && IsExcludedSourcePath(document.FilePath)) continue;

                var root = document.GetSyntaxRootAsync().GetAwaiter().GetResult();
                if (root == null)
                {
                    ReportSkipped(writer, $"문서 구문 트리를 읽을 수 없음: {document.FilePath ?? document.Name}");
                    continue;
                }

                var tryStatements = root.DescendantNodes().OfType<TryStatementSyntax>().ToList();
                if (!tryStatements.Any()) continue;

                var semanticModel = compilation.GetSemanticModel(root.SyntaxTree);
                var file = document.FilePath ?? document.Name;
                foreach (var tryStmt in tryStatements)
                {
                    var line = tryStmt.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                    // P1-6/P1-7: 분석 파이프라인과 동일한 수집기로 '예외 유발 노드' 유무 판정.
                    var dInvocations = new List<InvocationExpressionSyntax>();
                    var dCreations = new List<BaseObjectCreationExpressionSyntax>();
                    var dThrown = new List<ExpressionSyntax>();
                    var dAccess = new List<ExpressionSyntax>();
                    CollectThrowCapable(tryStmt.Block, dInvocations, dCreations, dThrown, dAccess);
                    if (dInvocations.Count == 0 && dCreations.Count == 0 && dThrown.Count == 0 && dAccess.Count == 0)
                    {
                        ReportSkipped(writer, $"{file}:{line} — try 블록에 예외 유발 노드가 없음");
                        continue;
                    }

                    var message = $"📄 파일: {file}, 줄: {line} → try 블록 내부 API 호출:";
                    Log(message);
                    writer.WriteLine(message);
                    methodExceptionList = AnalyzeTryBlock(tryStmt, semanticModel, writer, exceptionWriter, compilation);
                    EmitOrderedCatches(writer, compilation, methodExceptionList);
                }
            }
        }

        // 결과 저장 및 종료 메시지 출력
        writer.Flush();
        exceptionWriter.Flush();
        Log("📄 결과 저장 완료: " + outputPath);
    }

    // exMap 에 집계, writer/exceptionWriter 는 nullable — null 이면 파일/로그 출력 없이 순수 집계만 수행(RunFix 재사용).
    private static void AnalyzeInternalMethod(MethodDeclarationSyntax methodSyntax, SemanticModel semanticModel, StreamWriter? writer, StreamWriter? exceptionWriter, CSharpCompilation? compilation, string callerFullName, int depth, Dictionary<string, string> exMap)
    {
        var indent = new string(' ', depth * 4); // 재귀 깊이에 따라 들여쓰기

        // P1-6/P1-7: 메서드 본문(식 본문 포함)에서 실행 경계를 지키며 예외 유발 노드 수집.
        var invocations = new List<InvocationExpressionSyntax>();
        var creations = new List<BaseObjectCreationExpressionSyntax>();
        var thrownExpressions = new List<ExpressionSyntax>();
        var accessExpressions = new List<ExpressionSyntax>();
        SyntaxNode? bodyNode = (SyntaxNode?)methodSyntax.Body ?? methodSyntax.ExpressionBody;
        if (bodyNode != null)
            CollectThrowCapable(bodyNode, invocations, creations, thrownExpressions, accessExpressions);

        foreach (var innerCall in invocations)
        {
            var symbolInfo = semanticModel.GetSymbolInfo(innerCall);
            var innerSymbol = symbolInfo.Symbol as IMethodSymbol
                           ?? symbolInfo.CandidateSymbols.FirstOrDefault() as IMethodSymbol;

            if (innerSymbol == null) continue;

            var methodName = innerSymbol.Name;
            var methodFullName = $"{innerSymbol.ContainingNamespace}.{innerSymbol.ContainingType.Name}.{innerSymbol.Name}";

            if (writer != null)
            {
                writer.WriteLine($"{indent}🔄 내부 호출: {methodFullName}()");
                Log($"{indent}🔄 내부 호출: {methodFullName}()");
            }

            // 프레임워크 API 예외 추론
            var ns = innerSymbol.ContainingNamespace?.ToDisplayString();
            if (ns != null && (ns.StartsWith("System") || ns.StartsWith("Microsoft")))
            {
                // ③ 정확 docId 매칭 + P1-10 심볼 기반 대체 조회
                var docExceptions = LookupDocumentedExceptions(innerSymbol);
                if (docExceptions == null)
                {
                    if (writer != null)
                    {
                        writer.WriteLine($"    🔧 {methodFullName}() - 문서화되지 않은 메서드");
                        Log($"    🔧 {methodFullName}() - 문서화되지 않은 메서드");
                    }
                    continue;
                }

                var exceptionList = new List<KeyValuePair<string, string>>();
                foreach (var exception in docExceptions)
                {
                    exMap[exception.Key] = exception.Value;
                    if (!exceptionList.Any(item => item.Key == exception.Key))
                        exceptionList.Add(exception);
                }

                if (writer != null)
                {
                    foreach (var exception in exceptionList)
                    {
                        writer.WriteLine($"        → 예상 예외: {exception.Key}");
                        Log($"        → 예상 예외: {exception.Key}");
                    }
                }
            }
            else
            {
                // 중첩 사용자 정의 메서드면 재귀 호출
                var nextMethodSyntax = innerSymbol.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() as MethodDeclarationSyntax;
                if (nextMethodSyntax != null && depth < 5) // 최대 재귀 제한
                {
                    // FIX 2: 타 프로젝트/외부 정의 트리를 현재 컴파일의 GetSemanticModel 에 넘기면 ArgumentException.
                    var declTree = nextMethodSyntax.SyntaxTree;
                    SemanticModel? nextModel = null;
                    if (declTree == semanticModel.SyntaxTree) nextModel = semanticModel;
                    else if (compilation != null && compilation.ContainsSyntaxTree(declTree)) nextModel = compilation.GetSemanticModel(declTree);
                    if (nextModel != null)
                        AnalyzeInternalMethod(nextMethodSyntax, nextModel, writer, exceptionWriter, compilation, methodFullName, depth + 1, exMap);
                    else
                        ReportSkipped(writer, $"    ⤷ 재귀 분석 생략(타 프로젝트/외부 정의): {methodFullName}");
                }
            }
        }

        // P1-6+: 생성자·직접 throw·속성/인덱서 예외도 동일 exMap 으로 집계
        CollectFrameworkCreationExceptions(creations, semanticModel, exMap, writer);
        CollectThrownExpressionTypes(thrownExpressions, semanticModel, exMap, writer);
        CollectPropertyAccessExceptions(accessExpressions, semanticModel, exMap, writer);
    }

    // ── 추출된 재사용 코어 ① : bin\Debug + net472 기본 어셈블리 참조 목록 생성 (AnalyzeDirectory·RunFix 공용)
    public static List<MetadataReference> BuildReferences(string targetDirectory)
    {
        var references = new List<MetadataReference>();

        // P1-10: 형제 .xml 문서가 있으면 doc provider 를 붙여 폴더 모드에서도 심볼 XML 조회 가능.
        static MetadataReference Ref(string dllPath)
        {
            var xml = Path.ChangeExtension(dllPath, ".xml");
            return File.Exists(xml)
                ? MetadataReference.CreateFromFile(dllPath, documentation: XmlDocumentationProvider.CreateFromFile(xml))
                : MetadataReference.CreateFromFile(dllPath);
        }

        // 현재 프로젝트 bin\Debug 의 dll 추가 (필요 시 net472 등 서브폴더 포함)
        var dllPath = Path.Combine(targetDirectory, "bin", "Debug");
        if (Directory.Exists(dllPath))
        {
            var dlls = Directory.GetFiles(dllPath, "*.dll");
            var dllReferences = dlls.Select(path => Ref(path)).ToList();
            references.AddRange(dllReferences);
        }

        // ✅ .NET Framework 4.7.2의 필수 기본 어셈블리 (bin\Debug 미포함 GAC 기반 DLL 수동 지정)
        var net472Path = @"C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.7.2\";
        references.AddRange
                   (new[]
                   {
                        "mscorlib.dll",
                        "System.dll",
                        "System.Core.dll",
                        "System.Xml.dll",
                        "System.Net.Http.dll",
                        "PresentationFramework.dll",
                        "PresentationCore.dll",
                        "WindowsBase.dll",
                        "System.Xaml.dll"
                   }
                   .Select(name => Ref(Path.Combine(net472Path, name))));

        return references;
    }

    // ── 추출된 재사용 코어 ② : try 블록 내부 예외 집계 (type→한글설명 맵). writer 가 null 이면 순수 집계(무출력).
    public static Dictionary<string, string> AnalyzeTryBlock(TryStatementSyntax tryStmt, SemanticModel semanticModel, StreamWriter? writer = null, StreamWriter? exceptionWriter = null, CSharpCompilation? compilation = null)
    {
        var exMap = new Dictionary<string, string>();

        // P1-6/P1-7: 실행 경계(람다/로컬함수/중첩 try 보호블록)를 지키며 예외 유발 노드 수집.
        var invocations = new List<InvocationExpressionSyntax>();
        var creations = new List<BaseObjectCreationExpressionSyntax>();
        var thrownExpressions = new List<ExpressionSyntax>();
        var accessExpressions = new List<ExpressionSyntax>();
        CollectThrowCapable(tryStmt.Block, invocations, creations, thrownExpressions, accessExpressions);

        foreach (var call in invocations)
        {
            var symbolInfo = semanticModel.GetSymbolInfo(call);
            var methodSymbol = symbolInfo.Symbol as IMethodSymbol;

            if (methodSymbol == null) continue;

            var ns = methodSymbol.ContainingNamespace?.ToDisplayString();
            if (string.IsNullOrEmpty(ns)) continue;

            var methodFullName = $"{methodSymbol.ContainingNamespace}.{methodSymbol.ContainingType.Name}.{methodSymbol.Name}";

            if (ns.StartsWith("System") || ns.StartsWith("Microsoft"))
            {
                // ③ 정확 docId 매칭 + P1-10 심볼 기반 대체 조회
                var docExceptions = LookupDocumentedExceptions(methodSymbol);
                if (docExceptions == null) continue;

                var exceptionList = new List<KeyValuePair<string, string>>();
                foreach (var exception in docExceptions)
                {
                    exMap[exception.Key] = exception.Value;
                    if (!exceptionList.Any(item => item.Key == exception.Key))
                        exceptionList.Add(exception);
                }

                if (writer != null)
                {
                    foreach (var exception in exceptionList)
                    {
                        writer.WriteLine($"        → 예상 예외: {exception.Key}");
                        Log($"        → 예상 예외: {exception.Key}");
                    }
                }
            }
            else
            {
                var nonFrameworkCall = $"프레임워크에 등록되지 않은 API : {methodSymbol.ContainingNamespace}.{methodSymbol.ContainingType.Name}.{methodSymbol.Name}";
                if (writer != null)
                {
                    writer.WriteLine($"    🔧 {nonFrameworkCall}()");
                    Log($"    🔧 {nonFrameworkCall}()");
                }

                // 해당 메서드 정의 위치를 찾음 (재귀 분석용)
                var methodDeclSyntax = methodSymbol.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() as MethodDeclarationSyntax;

                if (methodDeclSyntax != null)
                {
                    // FIX 2: 타 프로젝트/외부 정의 트리를 현재 컴파일의 GetSemanticModel 에 넘기면 ArgumentException.
                    var declTree = methodDeclSyntax.SyntaxTree;
                    SemanticModel? methodModel = null;
                    if (declTree == semanticModel.SyntaxTree) methodModel = semanticModel;
                    else if (compilation != null && compilation.ContainsSyntaxTree(declTree)) methodModel = compilation.GetSemanticModel(declTree);
                    if (methodModel != null)
                        AnalyzeInternalMethod(methodDeclSyntax, methodModel, writer, exceptionWriter, compilation, methodFullName, 1, exMap);
                    else
                        ReportSkipped(writer, $"    ⤷ 재귀 분석 생략(타 프로젝트/외부 정의): {methodFullName}");
                }
            }
        }

        // P1-6+: 생성자·직접 throw·속성/인덱서 예외도 동일 exMap 으로 집계
        CollectFrameworkCreationExceptions(creations, semanticModel, exMap, writer);
        CollectThrownExpressionTypes(thrownExpressions, semanticModel, exMap, writer);
        CollectPropertyAccessExceptions(accessExpressions, semanticModel, exMap, writer);

        return exMap;
    }

    // ── 추출된 재사용 코어 ③ : System.Exception 필터 + 심볼 해석(미해석 제거) + 파생→기반 정렬된 전체 타입명 목록.
    public static List<string> GetOrderedResolvedCatchTypes(CSharpCompilation compilation, Dictionary<string, string> exMap)
    {
        // ⑥ remove ONLY System.Exception (catch-all). Keep SystemException/ApplicationException etc.
        var items = exMap.Where(kv => kv.Key != "System.Exception").ToList();

        // resolve each type to a symbol via the same compilation
        int Depth(INamedTypeSymbol s) { int d = 0; var t = s; while (t != null) { d++; t = t.BaseType; } return d; }
        var resolved = items
            .Select(kv => new { Name = kv.Key, Sym = compilation.GetTypeByMetadataName(kv.Key) })
            .Where(x => x.Sym != null)
            // ① derived-before-base: single-inheritance ⇒ a subtype is strictly deeper ⇒ depth DESC is a valid catch order
            .OrderByDescending(x => Depth(x.Sym!))
            .ThenBy(x => x.Name, StringComparer.Ordinal)
            .Select(x => x.Name)
            .ToList();

        return resolved;
    }

    private static void EmitOrderedCatches(StreamWriter writer, CSharpCompilation compilation, Dictionary<string, string> exMap)
    {
        // ⑥ remove ONLY System.Exception (catch-all). Keep SystemException/ApplicationException etc.
        var items = exMap.Where(kv => kv.Key != "System.Exception").ToList();

        if (items.Count == 0)
        {
            Emit(writer, "🐙 catch 권장: ⚠️ 추론된 구체 예외 없음 — 수동 검토 필요");
            return;
        }

        // 정렬·해석은 추출된 코어에 위임 (동작 동일)
        var orderedNames = GetOrderedResolvedCatchTypes(compilation, exMap);
        var unresolved = items
            .Where(kv => compilation.GetTypeByMetadataName(kv.Key) == null)
            .Select(kv => kv.Key)
            .ToList();

        // ⑤ Roslyn self-compile validation over the RESOLVED, ordered set
        var validation = ValidateCatchOrder(orderedNames, compilation);

        Emit(writer, "🐙 catch 권장 순서 (파생 → 기반, Exception 제외):");
        int i = 1;
        foreach (var name in orderedNames)
            Emit(writer, $"    {i++}. {ShortTypeName(name)} : {exMap[name]}");
        if (unresolved.Count > 0)
            Emit(writer, $"    ⚠️ 해석 불가(수동 확인 — 외부 라이브러리/미빌드): {string.Join(", ", unresolved.Select(ShortTypeName))}");
        Emit(writer, validation);

        Emit(writer, "── 붙여넣기용 스켈레톤 ──────────────────────");
        foreach (var name in orderedNames)
            Emit(writer, $"catch ({ShortTypeName(name)} ex) {{ /* {exMap[name]} */ }}");
    }

    // self-compile the synthesized try/catch; report CS0160 (already-caught) / CS0161 presence
    private static string ValidateCatchOrder(List<string> orderedFullNames, CSharpCompilation compilation)
    {
        if (orderedFullNames.Count == 0) return "        ✅ 셀프 컴파일 검증: 대상 없음";
        var sb = new StringBuilder();
        sb.AppendLine("class __CatchValidator__ { void __M__() { try { }");
        foreach (var t in orderedFullNames) sb.AppendLine($"catch (global::{t}) {{ }}");
        sb.AppendLine("} }");
        var vtree = CSharpSyntaxTree.ParseText(sb.ToString());
        var vcomp = CSharpCompilation.Create("CatchValidation")
            .WithOptions(new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary))
            .AddReferences(compilation.References)
            .AddSyntaxTrees(vtree);
        var errors = vcomp.GetDiagnostics()
            .Where(d => d.Severity == DiagnosticSeverity.Error && (d.Id == "CS0160" || d.Id == "CS0161"))
            .ToList();
        if (errors.Count == 0)
            return "        ✅ 셀프 컴파일 검증 통과 (CS0160/CS0161 없음)";
        return "        ⚠️ 셀프 컴파일 검증 실패: " + string.Join(", ", errors.Select(d => d.Id + " " + d.GetMessage()));
    }

    private static string ShortTypeName(string fullName)
    {
        var idx = fullName.LastIndexOf('.');
        return idx >= 0 ? fullName.Substring(idx + 1) : fullName;
    }

    private static void Emit(StreamWriter writer, string msg) { writer.WriteLine(msg); Log(msg); }

    // 헤드리스 게이트: PASS면 0, FAIL이면 1 반환. 전체 상세는 <BaseDir>\selftest-result.txt에 기록.
    // mode 는 "--selftest" 또는 "--selftest-xml". 기존 RunSelfTest/RunSelfTestXml 로직·판정 기준을 그대로 재사용.
    public static int RunSelfTestHeadless(string mode)
    {
        var sb = new StringBuilder();
        var sw = new StringWriter(sb);
        var originalOut = Console.Out;
        var originalLog = Log;
        Console.SetOut(sw);
        Log = Console.WriteLine; // Emit/Log 출력도 리다이렉트된 콘솔(=StringBuilder)로 수집
        try
        {
            if (mode == "--selftest-xml") RunSelfTestXml();
            else RunSelfTest();
        }
        catch (Exception ex)
        {
            sb.AppendLine("SELFTEST EXCEPTION: " + ex);
        }
        finally
        {
            Console.SetOut(originalOut);
            Log = originalLog;
        }

        var text = sb.ToString();
        // 기존 판정 기준 그대로: 최종 PASS 라인 존재 여부로 결정
        var passToken = mode == "--selftest-xml" ? "SELFTEST-XML PASS" : "SELFTEST PASS";
        bool pass = text.Contains(passToken);

        try
        {
            var resultPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "selftest-result.txt");
            File.WriteAllText(resultPath, text);
        }
        catch { /* 파일 기록 실패는 무시 */ }

        try { Console.WriteLine(text); } catch { /* 콘솔 없을 수 있음 */ }

        return pass ? 0 : 1;
    }

    private static void RunSelfTest()
    {
        var net472Path = @"C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.7.2\";
        var refs = new[] { "mscorlib.dll", "System.dll", "System.Core.dll" }
            .Select(n => (MetadataReference)MetadataReference.CreateFromFile(System.IO.Path.Combine(net472Path, n)));
        var comp = CSharpCompilation.Create("SelfTest").AddReferences(refs);

        // known set INCLUDING System.Exception (must be filtered) + a derived/base pair (order check)
        var exMap = new Dictionary<string, string>
        {
            ["System.Exception"] = "최상위(반드시 제외되어야 함)",
            ["System.ArgumentException"] = "인수 오류",
            ["System.ArgumentNullException"] = "인수 null (ArgumentException의 자식)",
            ["System.IO.IOException"] = "입출력 오류",
        };

        // capture EmitOrderedCatches output via an in-memory StreamWriter
        var ms = new System.IO.MemoryStream();
        var writer = new StreamWriter(ms) { AutoFlush = true };
        EmitOrderedCatches(writer, comp, exMap);
        writer.Flush();
        var output = System.Text.Encoding.UTF8.GetString(ms.ToArray());

        bool exceptionFiltered = !output.Contains("catch (Exception ");
        int idxNull = output.IndexOf("ArgumentNullException", StringComparison.Ordinal);
        int idxArg = output.IndexOf("catch (ArgumentException", StringComparison.Ordinal);
        bool derivedFirst = idxNull >= 0 && idxArg >= 0 && idxNull < idxArg;
        bool selfValidated = output.Contains("셀프 컴파일 검증 통과");

        Console.WriteLine("===== SELFTEST OUTPUT =====");
        Console.WriteLine(output);
        Console.WriteLine("===========================");
        Console.WriteLine($"[1] System.Exception 제거: {(exceptionFiltered ? "PASS" : "FAIL")}");
        Console.WriteLine($"[2] 파생 우선(ArgumentNullException < ArgumentException): {(derivedFirst ? "PASS" : "FAIL")}");
        Console.WriteLine($"[3] 셀프 컴파일 검증 통과 출력: {(selfValidated ? "PASS" : "FAIL")}");
        Console.WriteLine((exceptionFiltered && derivedFirst && selfValidated) ? "SELFTEST PASS" : "SELFTEST FAIL");
    }

    // ②③④ 핵심 XML 조회 경로 실증: GetDocumentationCommentId ↔ _apiDocCache 키 매칭 + ko 한글 메시지 통과
    private static void RunSelfTestXml()
    {
        // 1. 실제 ko XML 로드
        LoadXmlDocumentation();
        Console.WriteLine($"📚 _apiDocCache.Count = {_apiDocCache.Count}");
        if (_apiDocCache.Count == 0)
        {
            Console.WriteLine("SELFTEST-XML FAIL: XML 미로드");
            return;
        }

        // 2. 인메모리 소스 파싱
        var source = "class __T__ { void __M__() { try { int a = int.Parse(\"1\"); string s = System.IO.File.ReadAllText(\"a.txt\"); } catch { } } }";
        var tree = CSharpSyntaxTree.ParseText(source);

        // 3. net472 참조로 컴파일 생성 + SemanticModel 확보
        var net472Path = @"C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.7.2\";
        var refs = new[] { "mscorlib.dll", "System.dll", "System.Core.dll", "System.Xml.dll" }
            .Select(n => (MetadataReference)MetadataReference.CreateFromFile(System.IO.Path.Combine(net472Path, n)));
        var comp = CSharpCompilation.Create("SelfTestXml").AddReferences(refs).AddSyntaxTrees(tree);
        var semanticModel = comp.GetSemanticModel(tree);

        // 판정 플래그 (int.Parse 기준)
        bool parseDocFound = false;
        bool parseFormatKey = false;
        bool parseDescNonEmpty = false;
        bool readAllTextDocFound = false;

        // 4. try 블록 내부 호출 순회
        var tryStmt = tree.GetRoot().DescendantNodes().OfType<TryStatementSyntax>().FirstOrDefault();
        if (tryStmt == null)
        {
            Console.WriteLine("SELFTEST-XML FAIL: try 블록 없음");
            return;
        }

        var calls = tryStmt.Block.DescendantNodes().OfType<InvocationExpressionSyntax>().ToList();
        Console.WriteLine("===== SELFTEST-XML 조회 결과 =====");
        foreach (var call in calls)
        {
            var sym = semanticModel.GetSymbolInfo(call).Symbol as IMethodSymbol;
            if (sym == null)
            {
                Console.WriteLine($"  (심볼 해석 실패: {call})");
                continue;
            }

            var methodName = sym.Name;
            var docId = sym.GetDocumentationCommentId();
            Console.WriteLine($"  호출: {sym.ContainingType.Name}.{methodName}");
            Console.WriteLine($"    docId = {docId ?? "(null)"}");

            bool found = docId != null && _apiDocCache.TryGetValue(docId, out var doc);
            Console.WriteLine($"    _apiDocCache 조회: {(found ? "FOUND" : "NOT FOUND")}");

            ApiDocumentation? matchedDoc = null;
            if (found) { _apiDocCache.TryGetValue(docId!, out matchedDoc); }

            if (found && matchedDoc != null)
            {
                Console.WriteLine($"    Exceptions.Count = {matchedDoc.Exceptions.Count}");
                var first = matchedDoc.Exceptions.FirstOrDefault();
                if (matchedDoc.Exceptions.Count > 0)
                    Console.WriteLine($"    첫 예외 → {first.Key} : {first.Value}");
            }

            if (methodName == "Parse" && sym.ContainingType.Name == "Int32")
            {
                parseDocFound = found;
                if (found && matchedDoc != null)
                {
                    parseFormatKey = matchedDoc.Exceptions.ContainsKey("System.FormatException");
                    if (parseFormatKey)
                        parseDescNonEmpty = !string.IsNullOrWhiteSpace(matchedDoc.Exceptions["System.FormatException"]);
                }
            }
            if (methodName == "ReadAllText" && sym.ContainingType.Name == "File")
            {
                readAllTextDocFound = found;
            }
        }
        Console.WriteLine("=================================");

        // 5~6. 판정 (int.Parse만 필수, File.ReadAllText는 참고용)
        Console.WriteLine($"[a] int.Parse docId 조회 성공: {(parseDocFound ? "PASS" : "FAIL")}");
        Console.WriteLine($"[b] System.FormatException 키 존재: {(parseFormatKey ? "PASS" : "FAIL")}");
        Console.WriteLine($"[c] 설명(한글) 비어있지 않음: {(parseDescNonEmpty ? "PASS" : "FAIL")}");
        Console.WriteLine($"[참고] File.ReadAllText docId 조회: {(readAllTextDocFound ? "FOUND" : "NOT FOUND")}");
        Console.WriteLine((parseDocFound && parseFormatKey && parseDescNonEmpty) ? "SELFTEST-XML PASS" : "SELFTEST-XML FAIL");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // FIX 엔진: 과도하게 넓은 catch(Exception) 을 정렬된 구체 catch 로 결정론적 치환
    // ══════════════════════════════════════════════════════════════════════════

    public class FixResult
    {
        public int Modified;
        public int Skipped_NonTrivial;
        public int Skipped_Empty;
        public int Skipped_NotBroad;
        public int CompileReverted;
        public List<string> PreviewBlocks = new List<string>();
        public List<string> ManualReview = new List<string>();
        // P1-11: 완전성(completeness) 추적 — 워크스페이스 로드 실패/건너뛴 문서가 있으면 부분 수행.
        public List<string> WorkspaceFailures = new List<string>();
        public int SkippedDocuments;
        public bool IsComplete => WorkspaceFailures.Count == 0 && SkippedDocuments == 0;
    }

    // 단일 catch 가 과도하게 넓은지 판정: bare catch {} 또는 선언 타입이 System.Exception.
    private static bool IsOverBroadCatch(CatchClauseSyntax c, SemanticModel model)
    {
        if (c.Declaration == null) return true; // catch { }
        var typeText = c.Declaration.Type.ToString();
        if (typeText == "Exception" || typeText == "System.Exception") return true;
        var sym = model.GetTypeInfo(c.Declaration.Type).Type;
        if (sym != null && sym.ToDisplayString() == "System.Exception") return true;
        return false;
    }

    // catch 본문이 치환-안전한지: 0개 문 또는 정확히 1개의 (호출식)ExpressionStatement.
    private static bool IsReplaceSafeBody(CatchClauseSyntax c)
    {
        var stmts = c.Block.Statements;
        if (stmts.Count == 0) return true;
        if (stmts.Count == 1 && stmts[0] is ExpressionStatementSyntax es && es.Expression is InvocationExpressionSyntax) return true;
        return false;
    }

    // 원본 try 를 유지하고 catch 절만 정렬된 구체 예외들로 교체한 새 TryStatement 를 생성.
    // original 은 (자식 fix 가 이미 반영된) rewritten try 일 수 있으며, 그 .Block/.Finally 를 그대로 사용해 자식 fix 를 보존한다.
    private static TryStatementSyntax BuildReplacementTry(TryStatementSyntax original, List<string> fullTypeNames, string eol)
    {
        var sb = new StringBuilder();
        sb.Append("try ");
        sb.Append(original.Block.ToString()); // try 본문 그대로 (변경 없음)
        sb.Append(eol);
        foreach (var t in fullTypeNames)
        {
            // 완전수식 타입 + 완전수식 Debug 호출 (using 추가 없음)
            sb.Append($"catch ({t} ex) {{ System.Diagnostics.Debug.WriteLine(ex); /* [AUTO-CATCH] 로거로 교체 */ }}").Append(eol);
        }
        if (original.Finally != null)
        {
            sb.Append(original.Finally.ToString()); // finally 보존
            sb.Append(eol);
        }
        return (TryStatementSyntax)SyntaxFactory.ParseStatement(sb.ToString());
    }

    private static string BuildPreviewBlock(string file, int line, string before, string after)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"📄 {file}:{line}");
        sb.AppendLine("--- BEFORE ---");
        sb.AppendLine(before);
        sb.AppendLine("--- AFTER ---");
        sb.AppendLine(after);
        return sb.ToString();
    }

    // P1-9: 위치는 라인 시프트 때문에 제외 — Id+메시지 멀티셋 비교로 '같은 ID의 신규 오류'까지 검출.
    internal static List<string> DiffIntroducedErrors(IEnumerable<Diagnostic> before, IEnumerable<Diagnostic> after)
    {
        static string Fp(Diagnostic d) => d.Id + "|" + d.GetMessage();
        var baseCounts = before.Where(d => d.Severity == DiagnosticSeverity.Error).GroupBy(Fp).ToDictionary(g => g.Key, g => g.Count());
        return after.Where(d => d.Severity == DiagnosticSeverity.Error).GroupBy(Fp)
            .Where(g => g.Count() > baseCounts.GetValueOrDefault(g.Key, 0))
            .Select(g => g.Key).ToList();
    }

    private static void ProcessFixRoot(FixResult res, string file, SyntaxNode root, SemanticModel semanticModel, CSharpCompilation compilation, bool apply, Encoding enc, string eol)
    {
        var tries = root.DescendantNodes().OfType<TryStatementSyntax>().ToList();
        if (tries.Count == 0) return;

        // FIX 3: 사전 빌드한 newTry 대신 (원본 try → 구체 타입/키) 매핑만 수집하고,
        // 실제 치환은 ReplaceNodes 콜백의 rewritten 인자로 만들어 자식 fix 를 보존한다.
        var typesFor = new Dictionary<TryStatementSyntax, List<string>>();
        var keyFor = new Dictionary<TryStatementSyntax, string>();
        var origFor = new Dictionary<string, (string beforeText, int line)>(); // key → (원본 미리보기, 줄)
        int idx = 0;

        foreach (var tryStmt in tries)
        {
            var catches = tryStmt.Catches;
            var line = tryStmt.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

            // 단일 catch 만 대상 (finally 는 허용). 0개/다중 catch → not-broad.
            if (catches.Count != 1)
            {
                res.Skipped_NotBroad++;
                res.ManualReview.Add($"{file}:{line} (건너뜀: catch가 1개가 아님)");
                continue;
            }

            var theCatch = catches[0];
            if (!IsOverBroadCatch(theCatch, semanticModel))
            {
                res.Skipped_NotBroad++;
                continue;
            }

            // 과도하게 넓지만 본문이 치환-불안전 → 수동 검토
            if (!IsReplaceSafeBody(theCatch))
            {
                res.ManualReview.Add($"{file}:{line}");
                res.Skipped_NonTrivial++;
                continue;
            }

            // 적격 대상: 구체 예외 추론
            var exMap = AnalyzeTryBlock(tryStmt, semanticModel, compilation: compilation);
            var types = GetOrderedResolvedCatchTypes(compilation, exMap);
            if (types.Count == 0)
            {
                // catch-less try 를 절대 만들지 않음
                res.Skipped_Empty++;
                res.ManualReview.Add($"{file}:{line} (건너뜀: 추론된 구체 예외 없음)");
                continue;
            }

            var key = (idx++).ToString();
            typesFor[tryStmt] = types;
            keyFor[tryStmt] = key;
            origFor[key] = (tryStmt.ToString(), line);
        }

        if (typesFor.Count == 0) return;

        const string FixAnno = "AUTO-CATCH-FIX";
        var newRoot = root.ReplaceNodes(
            typesFor.Keys,
            (orig, rewritten) => BuildReplacementTry((TryStatementSyntax)rewritten, typesFor[orig], eol)
                .WithTriviaFrom(orig)
                .WithAdditionalAnnotations(Microsoft.CodeAnalysis.Formatting.Formatter.Annotation,
                                           new SyntaxAnnotation(FixAnno, keyFor[orig])));

        // FIX 3(P2-13 format part): 주석 범위 포매팅 — 새 노드만 정렬, 나머지 파일은 바이트 보존.
        var workspace = new AdhocWorkspace();
        var options = workspace.Options.WithChangedOption(Microsoft.CodeAnalysis.Formatting.FormattingOptions.NewLine, LanguageNames.CSharp, eol);
        var formattedRoot = Microsoft.CodeAnalysis.Formatting.Formatter.Format(newRoot, Microsoft.CodeAnalysis.Formatting.Formatter.Annotation, workspace, options);
        var formattedText = formattedRoot.ToFullString();

        var origDiagnostics = compilation.GetDiagnostics();

        var newTree = CSharpSyntaxTree.ParseText(formattedText, (CSharpParseOptions?)root.SyntaxTree.Options, root.SyntaxTree.FilePath, enc);
        var newComp = compilation.ReplaceSyntaxTree(root.SyntaxTree, newTree);
        // P1-9: Id+메시지 멀티셋 지문으로 신규 오류 검출 (같은 ID의 추가 오류도 잡음).
        var introduced = DiffIntroducedErrors(origDiagnostics, newComp.GetDiagnostics());

        if (introduced.Count > 0)
        {
            res.CompileReverted++;
            var ids = introduced.Select(fp => fp.Split('|')[0]).Distinct();
            res.ManualReview.Add($"{file} (컴파일 롤백: {string.Join(",", ids)})");
            return;
        }

        // FIX 3 step4: 치환 후 주석 노드에서 미리보기 생성 (줄 순서). 중첩 자식은 부모 노드 텍스트에 흡수됨.
        var annotated = newRoot.GetAnnotatedNodes(FixAnno).ToList();
        var previews = new List<(int line, string block)>();
        foreach (var node in annotated)
        {
            var key = node.GetAnnotations(FixAnno).First().Data;
            if (key != null && origFor.TryGetValue(key, out var of))
                previews.Add((of.line, BuildPreviewBlock(file, of.line, of.beforeText, node.ToString())));
        }
        previews.Sort((a, b) => a.line.CompareTo(b.line));
        res.PreviewBlocks.AddRange(previews.Select(p => p.block));

        // 치환된 과도-넓음 catch 수 = 적격 try 수 (중첩 자식은 부모 재구성 시 텍스트로 흡수되어 주석이 소실될 수 있으므로
        // 주석 노드 수가 아닌 typesFor.Count 로 집계한다 — 중첩 케이스에서 실제 치환 건수를 정확히 반영).
        res.Modified += typesFor.Count;

        if (apply)
        {
            File.WriteAllText(file, formattedText, enc);
        }
    }

    private static FixResult RunFixSolution(string solutionPath, bool apply)
    {
        EnsureCodePagesRegistered();
        var res = new FixResult();
        // P1-11: 워크스페이스 로드 실패를 res 에 수집하려면 res 를 워크스페이스 생성 전에 선언해야 한다.
        using var workspace = OpenSolutionWorkspace(solutionPath, out var resolvedSolutionPath, msg => res.WorkspaceFailures.Add(msg));
        var solution = workspace.OpenSolutionAsync(resolvedSolutionPath).GetAwaiter().GetResult();

        Log($"🔧 솔루션 수정 시작: {resolvedSolutionPath}");

        // P2-12: 링크 파일/다중 프로젝트 컨텍스트로 같은 물리 파일이 반복 등장하면 최초 1회만 수정.
        var processedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var project in solution.Projects.Where(p => p.Language == LanguageNames.CSharp))
        {
            var compilation = project.GetCompilationAsync().GetAwaiter().GetResult() as CSharpCompilation;
            if (compilation == null)
            {
                res.ManualReview.Add($"{project.Name} (건너뜀: 프로젝트 컴파일 생성 실패)");
                res.SkippedDocuments += project.Documents.Count();
                continue;
            }

            foreach (var document in project.Documents)
            {
                var file = document.FilePath;
                if (string.IsNullOrWhiteSpace(file) || !File.Exists(file))
                {
                    // P1-11: 조용한 continue 대신 완전성 판정을 위해 건너뜀을 기록.
                    res.SkippedDocuments++;
                    res.ManualReview.Add($"{document.Name} (건너뜀: 파일 경로 없음)");
                    continue;
                }

                // FIX 5: obj/bin/.git·생성 파일 제외
                if (IsExcludedSourcePath(file)) continue;

                // P2-12: 물리 경로 기준 중복 제거
                var full = Path.GetFullPath(file);
                if (!processedFiles.Add(full))
                {
                    res.ManualReview.Add($"{full} (중복 프로젝트 컨텍스트 — 최초 1회만 수정)");
                    continue;
                }

                var root = document.GetSyntaxRootAsync().GetAwaiter().GetResult();
                if (root == null)
                {
                    res.ManualReview.Add($"{document.Name} (건너뜀: 구문 트리 없음)");
                    continue;
                }

                // FIX 4: 워크스페이스 root 를 구문 소스로 쓰되, 파일 바이트에서 (인코딩, EOL) 만 감지해 보존 되쓰기.
                var (_, enc, eol) = ReadSourcePreserving(file);
                var semanticModel = compilation.GetSemanticModel(root.SyntaxTree);
                ProcessFixRoot(res, file, root, semanticModel, compilation, apply, enc, eol);
            }
        }

        return res;
    }

    public static FixResult RunFix(string target, bool apply, bool allowSourceOnlyFallback = false)
    {
        if (_apiDocCache.Count == 0)
        {
            LoadXmlDocumentation();
        }

        var solutionPath = TryResolveSingleSolutionPath(target);
        if (solutionPath != null) return RunFixSolution(solutionPath, apply);
        if (!allowSourceOnlyFallback)
        {
            // 분석 경로(ResolveSolutionPath)와 동일하게 명시적으로 실패시킨다 — 조용한 폴더 확대 금지.
            // ResolveSolutionPath(target) 를 호출하면 0개/복수 .sln 에 맞는 한국어 예외 메시지가 던져진다.
            ResolveSolutionPath(target); // always throws here (sln==1 case was handled above)
            throw new InvalidOperationException($"솔루션을 확정할 수 없습니다: {target}"); // unreachable safety
        }

        // (이하 기존 폴더 모드 유지 — FIX 4 인코딩 보존 + FIX 5 제외 필터 적용)
        EnsureCodePagesRegistered();
        var res = new FixResult();

        var references = BuildReferences(target);
        var csFiles = Directory.GetFiles(target, "*.cs", SearchOption.AllDirectories);

        foreach (var file in csFiles)
        {
            if (IsExcludedSourcePath(file)) continue;

            var (code, enc, eol) = ReadSourcePreserving(file);
            var tree = CSharpSyntaxTree.ParseText(code);
            var root = tree.GetRoot();

            var compilation = CSharpCompilation.Create("Fix")
                .AddReferences(references)
                .AddSyntaxTrees(tree);
            var semanticModel = compilation.GetSemanticModel(tree);

            ProcessFixRoot(res, file, root, semanticModel, compilation, apply, enc, eol);
        }

        return res;
    }

    public static void WriteFixReport(FixResult res, bool apply)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"===== EXCEPTION FIX REPORT MODE={(apply ? "APPLY" : "PREVIEW")} =====");
        sb.AppendLine($"Modified            : {res.Modified}");
        sb.AppendLine($"Skipped_NonTrivial  : {res.Skipped_NonTrivial}");
        sb.AppendLine($"Skipped_Empty       : {res.Skipped_Empty}");
        sb.AppendLine($"Skipped_NotBroad    : {res.Skipped_NotBroad}");
        sb.AppendLine($"CompileReverted     : {res.CompileReverted}");
        sb.AppendLine($"SkippedDocuments    : {res.SkippedDocuments}");
        sb.AppendLine($"Completeness       : {(res.IsComplete ? "Complete" : "PARTIAL")}");
        sb.AppendLine();
        if (res.WorkspaceFailures.Count > 0)
        {
            sb.AppendLine("----- WORKSPACE FAILURES -----");
            foreach (var wf in res.WorkspaceFailures) sb.AppendLine(wf);
            sb.AppendLine();
        }
        sb.AppendLine("----- PREVIEW BLOCKS -----");
        foreach (var b in res.PreviewBlocks)
        {
            sb.AppendLine(b);
            sb.AppendLine();
        }
        sb.AppendLine("----- MANUAL REVIEW (과도-넓음이나 비자명 → 사람 확인) -----");
        if (res.ManualReview.Count == 0) sb.AppendLine("(없음)");
        foreach (var m in res.ManualReview) sb.AppendLine(m);

        var text = sb.ToString();
        try
        {
            var reportPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "fix-report.txt");
            File.WriteAllText(reportPath, text);
        }
        catch { /* 파일 기록 실패 무시 */ }

        try { Console.WriteLine(text); } catch { /* 콘솔 없을 수 있음 */ }
    }

    // ── --selftest-fix 헤드리스 하니스: 임시 픽스처 생성 → preview/apply → [1]-[6] 검증 → 0/1 반환
    public static int RunSelfTestFix()
    {
        var sb = new StringBuilder();
        void L(string m) { sb.AppendLine(m); }

        string fixtureDir = Path.Combine(Path.GetTempPath(), "ea_fix_selftest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fixtureDir);

        bool allPass = false;
        try
        {
            var broadPath = Path.Combine(fixtureDir, "Broad.cs");
            var emptyPath = Path.Combine(fixtureDir, "Empty.cs");
            var nonTrivialPath = Path.Combine(fixtureDir, "NonTrivial.cs");
            var specificPath = Path.Combine(fixtureDir, "Specific.cs");

            // 과도-넓음 + 치환-안전(단일 호출식)
            File.WriteAllText(broadPath,
                "using System;\n" +
                "class Broad\n{\n    void M(string s)\n    {\n" +
                "        try { int n = int.Parse(s); }\n" +
                "        catch (Exception ex) { LogUtil.Error(ex); }\n" +
                "    }\n}\n");

            // 과도-넓음 + 빈 본문 → 적격
            File.WriteAllText(emptyPath,
                "using System;\n" +
                "class EmptyC\n{\n    void M(string s)\n    {\n" +
                "        try { int n = int.Parse(s); }\n" +
                "        catch { }\n" +
                "    }\n}\n");

            // 과도-넓음이나 다중 문/return → 건너뛰고 ManualReview
            File.WriteAllText(nonTrivialPath,
                "using System;\n" +
                "class NonTrivialC\n{\n    void M(string s)\n    {\n" +
                "        try { int n = int.Parse(s); }\n" +
                "        catch (Exception ex) { Cleanup(); return; }\n" +
                "    }\n    void Cleanup() { }\n}\n");

            // 이미 구체 타입 → 손대지 않음
            File.WriteAllText(specificPath,
                "using System;\n" +
                "class SpecificC\n{\n    void M(string s)\n    {\n" +
                "        try { int n = int.Parse(s); }\n" +
                "        catch (FormatException ex) { }\n" +
                "    }\n}\n");

            var files = new[] { broadPath, emptyPath, nonTrivialPath, specificPath };
            var before = files.ToDictionary(f => f, f => File.ReadAllText(f));

            // 2. preview → 디스크 변경 없어야 함
            var previewRes = RunFix(fixtureDir, false, allowSourceOnlyFallback: true);
            bool previewUnchanged = files.All(f => File.ReadAllText(f) == before[f]);
            L($"[preview] 디스크 미변경: {(previewUnchanged ? "PASS" : "FAIL")} (Modified 미리보기={previewRes.Modified})");

            // 3. apply
            var res = RunFix(fixtureDir, true, allowSourceOnlyFallback: true);

            var broadText = File.ReadAllText(broadPath);
            var emptyText = File.ReadAllText(emptyPath);
            var nonTrivialText = File.ReadAllText(nonTrivialPath);
            var specificText = File.ReadAllText(specificPath);

            bool bareCatch(string t) => System.Text.RegularExpressions.Regex.IsMatch(t, @"catch\s*\{");

            // [1] Broad: 구체 3종 + Debug.WriteLine, Exception/bare 없음
            bool t1 = broadText.Contains("catch (System.ArgumentNullException ex)")
                   && broadText.Contains("catch (System.FormatException ex)")
                   && broadText.Contains("catch (System.OverflowException ex)")
                   && broadText.Contains("System.Diagnostics.Debug.WriteLine(ex)")
                   && !broadText.Contains("catch (System.Exception")
                   && !broadText.Contains("catch (Exception")
                   && !bareCatch(broadText);

            // [2] Broad.cs 컴파일 (CS0160 없음)
            var bt = CSharpSyntaxTree.ParseText(broadText);
            var bc = CSharpCompilation.Create("BroadCheck").AddReferences(BuildReferences(fixtureDir)).AddSyntaxTrees(bt);
            bool t2 = !bc.GetDiagnostics().Any(d => d.Id == "CS0160");

            // [3] NonTrivial 미변경 + ManualReview 등재
            bool t3 = nonTrivialText == before[nonTrivialPath]
                   && res.ManualReview.Any(m => m.Contains("NonTrivial.cs"))
                   && res.Skipped_NonTrivial >= 1;

            // [4] Specific 미변경 + Skipped_NotBroad
            bool t4 = specificText == before[specificPath] && res.Skipped_NotBroad >= 1;

            // [5] Broad 에 using System.Diagnostics; 추가 안 됨
            bool t5 = !broadText.Contains("using System.Diagnostics;");

            // [6] Empty 변경 → 구체 catch + Debug.WriteLine
            bool t6 = emptyText != before[emptyPath]
                   && emptyText.Contains("System.Diagnostics.Debug.WriteLine(ex)")
                   && emptyText.Contains("catch (System.FormatException ex)")
                   && !bareCatch(emptyText);

            L("===== SELFTEST-FIX 결과 =====");
            L($"FixResult: Modified={res.Modified}, Skipped_NonTrivial={res.Skipped_NonTrivial}, Skipped_Empty={res.Skipped_Empty}, Skipped_NotBroad={res.Skipped_NotBroad}, CompileReverted={res.CompileReverted}");
            L("--- ManualReview ---");
            foreach (var m in res.ManualReview) L("  " + m);
            L("--- Broad.cs (after) ---");
            L(broadText);
            L("--- Empty.cs (after) ---");
            L(emptyText);
            L("=============================");
            L($"[1] Broad → 구체 3종 + Debug.WriteLine, Exception/bare 제거: {(t1 ? "PASS" : "FAIL")}");
            L($"[2] Broad.cs 컴파일(CS0160 없음): {(t2 ? "PASS" : "FAIL")}");
            L($"[3] NonTrivial 미변경 + ManualReview: {(t3 ? "PASS" : "FAIL")}");
            L($"[4] Specific 미변경 (Skipped_NotBroad): {(t4 ? "PASS" : "FAIL")}");
            L($"[5] Broad 에 using System.Diagnostics; 미추가: {(t5 ? "PASS" : "FAIL")}");
            L($"[6] Empty 변경 → 구체 catch + Debug.WriteLine: {(t6 ? "PASS" : "FAIL")}");

            // ── [7] nested-try : 부모/자식 broad 모두 치환, Modified==2, 재컴파일 CS0160 없음 ──
            var nestedDir = Path.Combine(fixtureDir, "nested");
            Directory.CreateDirectory(nestedDir);
            var nestedPath = Path.Combine(nestedDir, "Nested.cs");
            File.WriteAllText(nestedPath,
                "using System;\n" +
                "class N {\n" +
                "    void M(string s) {\n" +
                "        try {\n" +
                "            try { int a = int.Parse(s); } catch (Exception ex) { Log(ex); }\n" +
                "            int b = int.Parse(s);\n" +
                "        } catch (Exception ex) { Log(ex); }\n" +
                "    }\n" +
                "    void Log(Exception e) { }\n" +
                "}\n");
            var nestedRes = RunFix(nestedDir, true, allowSourceOnlyFallback: true);
            var nestedText = File.ReadAllText(nestedPath);
            int autoCatchCount = System.Text.RegularExpressions.Regex.Matches(nestedText, @"\[AUTO-CATCH\]").Count;
            bool nestedNoBroad = !nestedText.Contains("catch (Exception ");
            var nestedTree = CSharpSyntaxTree.ParseText(nestedText);
            var nestedComp = CSharpCompilation.Create("NestedCheck").AddReferences(BuildReferences(nestedDir)).AddSyntaxTrees(nestedTree);
            bool nestedNoCs0160 = !nestedComp.GetDiagnostics().Any(d => d.Id == "CS0160");
            bool t7 = nestedNoBroad && autoCatchCount >= 2 && nestedRes.Modified == 2 && nestedNoCs0160;
            L($"[7] nested-try: {(t7 ? "PASS" : "FAIL")} (Modified={nestedRes.Modified}, autoCatch={autoCatchCount}, noBroad={nestedNoBroad}, noCS0160={nestedNoCs0160})");

            // ── [8] cross-project guard (in-memory, no MSBuild) : 외부 트리 심볼로 AnalyzeTryBlock 이 예외 없이 통과 ──
            var xNet472 = @"C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.7.2\";
            var xRefs = new[] { "mscorlib.dll", "System.dll", "System.Core.dll" }
                .Select(n => (MetadataReference)MetadataReference.CreateFromFile(Path.Combine(xNet472, n)))
                .ToList();
            var srcB = "namespace ExtLib { public class Lib { public static void M(string s) { int.Parse(s); } } }";
            var treeB = CSharpSyntaxTree.ParseText(srcB);
            var compB = CSharpCompilation.Create("compB")
                .WithOptions(new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary))
                .AddReferences(xRefs)
                .AddSyntaxTrees(treeB);
            var srcA = "using System;\nclass A { void F(string s) { try { ExtLib.Lib.M(s); } catch (Exception ex) { Log(ex); } } void Log(Exception e) { } }";
            var treeA = CSharpSyntaxTree.ParseText(srcA);
            var refsA = new List<MetadataReference>(xRefs) { compB.ToMetadataReference() };
            var compA = CSharpCompilation.Create("compA")
                .WithOptions(new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary))
                .AddReferences(refsA)
                .AddSyntaxTrees(treeA);
            var modelA = compA.GetSemanticModel(treeA);
            var tryStmtA = treeA.GetRoot().DescendantNodes().OfType<TryStatementSyntax>().First();
            bool t8;
            try { AnalyzeTryBlock(tryStmtA, modelA, compilation: compA); t8 = true; }
            catch (Exception ex) { t8 = false; L("  [8] 예외 발생: " + ex.GetType().Name + " — " + ex.Message); }
            L($"[8] cross-project guard (예외 없음): {(t8 ? "PASS" : "FAIL")}");

            // ── [9] encoding preservation : BOM+CRLF / no-BOM / CP949 보존 ──
            EnsureCodePagesRegistered();
            var encDir = Path.Combine(fixtureDir, "enc");
            Directory.CreateDirectory(encDir);
            string EligibleSrc(string cls, string extraComment) =>
                "using System;\n" + extraComment +
                "class " + cls + " { void M(string s) { try { int n = int.Parse(s); } catch (Exception ex) { Log(ex); } } void Log(Exception e) { } }\n";

            var bomPath = Path.Combine(encDir, "EncBomCrlf.cs");
            var bomText = EligibleSrc("C_a", "").Replace("\n", "\r\n");
            File.WriteAllText(bomPath, bomText, new UTF8Encoding(true));

            var noBomPath = Path.Combine(encDir, "EncNoBom.cs");
            File.WriteAllText(noBomPath, EligibleSrc("C_b", ""), new UTF8Encoding(false));

            var cp949Path = Path.Combine(encDir, "EncCp949.cs");
            var cp949 = Encoding.GetEncoding(949);
            File.WriteAllText(cp949Path, EligibleSrc("C_c", "// 한글주석확인\n"), cp949);

            var encRes = RunFix(encDir, true, allowSourceOnlyFallback: true);

            var bomBytes = File.ReadAllBytes(bomPath);
            bool bomKept = bomBytes.Length >= 3 && bomBytes[0] == 0xEF && bomBytes[1] == 0xBB && bomBytes[2] == 0xBF;
            bool crlfKept = true;
            for (int i = 0; i < bomBytes.Length; i++)
                if (bomBytes[i] == 0x0A && (i == 0 || bomBytes[i - 1] != 0x0D)) { crlfKept = false; break; }
            bool aOk = bomKept && crlfKept;

            var noBomBytes = File.ReadAllBytes(noBomPath);
            bool bOk = !(noBomBytes.Length >= 3 && noBomBytes[0] == 0xEF && noBomBytes[1] == 0xBB && noBomBytes[2] == 0xBF);

            var cp949After = cp949.GetString(File.ReadAllBytes(cp949Path));
            bool cOk = cp949After.Contains("한글주석확인");

            bool t9 = aOk && bOk && cOk && encRes.Modified >= 3;
            L($"[9] encoding preservation: {(t9 ? "PASS" : "FAIL")} (BOM/CRLF={aOk}, noBOM={bOk}, cp949={cOk}, Modified={encRes.Modified})");

            // ── [10] format scope : 무관한 이상포맷 라인 보존 ──
            var fmtDir = Path.Combine(fixtureDir, "format");
            Directory.CreateDirectory(fmtDir);
            var fmtPath = Path.Combine(fmtDir, "Fmt.cs");
            File.WriteAllText(fmtPath,
                "using System;\n" +
                "class C_fmt {\n" +
                "    void A(string s) { try { int n = int.Parse(s); } catch (Exception ex) { Log(ex); } }\n" +
                "    void B() { int    weird=1 ; }\n" +
                "    void Log(Exception e) { }\n" +
                "}\n");
            var fmtRes = RunFix(fmtDir, true, allowSourceOnlyFallback: true);
            var fmtText = File.ReadAllText(fmtPath);
            bool weirdKept = fmtText.Contains("int    weird=1 ;");
            bool t10 = weirdKept && fmtRes.Modified == 1;
            L($"[10] format scope: {(t10 ? "PASS" : "FAIL")} (weird 보존={weirdKept}, Modified={fmtRes.Modified})");

            // ── [11] no silent fallback : sln 없는 폴더 → allow:false 는 예외, allow:true 는 성공 ──
            var fbDir = Path.Combine(fixtureDir, "fallback");
            Directory.CreateDirectory(fbDir);
            File.WriteAllText(Path.Combine(fbDir, "Fb.cs"),
                "using System;\nclass Fb { void M(string s) { try { int n = int.Parse(s); } catch (Exception ex) { Log(ex); } } void Log(Exception e) { } }\n");
            bool t11a;
            try { RunFix(fbDir, false, allowSourceOnlyFallback: false); t11a = false; L("  [11] 예외 미발생(예상: InvalidOperationException)"); }
            catch (InvalidOperationException) { t11a = true; }
            catch (Exception ex) { t11a = false; L("  [11] 잘못된 예외: " + ex.GetType().Name); }
            bool t11b;
            try { RunFix(fbDir, false, allowSourceOnlyFallback: true); t11b = true; }
            catch (Exception ex) { t11b = false; L("  [11] allow:true 인데 예외: " + ex.GetType().Name); }
            bool t11 = t11a && t11b;
            L($"[11] no silent fallback: {(t11 ? "PASS" : "FAIL")} (throw={t11a}, allowOk={t11b})");

            // ── [12] excluded paths : obj\Gen.g.cs 는 수정 대상에서 제외 (바이트 불변) ──
            var exDir = Path.Combine(fixtureDir, "excluded");
            var objDir = Path.Combine(exDir, "obj");
            Directory.CreateDirectory(objDir);
            var genPath = Path.Combine(objDir, "Gen.g.cs");
            File.WriteAllText(genPath,
                "using System;\nclass Gen { void M(string s) { try { int n = int.Parse(s); } catch (Exception ex) { Log(ex); } } void Log(Exception e) { } }\n");
            var genBefore = File.ReadAllBytes(genPath);
            var exRes = RunFix(exDir, true, allowSourceOnlyFallback: true);
            var genAfter = File.ReadAllBytes(genPath);
            bool bytesEqual = genBefore.SequenceEqual(genAfter);
            bool t12 = bytesEqual && exRes.Modified == 0;
            L($"[12] excluded paths (obj\\Gen.g.cs 미변경): {(t12 ? "PASS" : "FAIL")} (bytesEqual={bytesEqual}, Modified={exRes.Modified})");

            // ── [13] 생성자 예외 수집 : StreamWriter(string) 생성자 문서 예외가 구체 catch 로 반영 ──
            var ctorDir = Path.Combine(fixtureDir, "ctor");
            Directory.CreateDirectory(ctorDir);
            var ctorPath = Path.Combine(ctorDir, "Ctor.cs");
            File.WriteAllText(ctorPath,
                "using System;\n" +
                "class Ct {\n" +
                "    void M(string s) {\n" +
                "        try { var sw = new System.IO.StreamWriter(s); sw.Dispose(); } catch (Exception ex) { Log(ex); }\n" +
                "    }\n" +
                "    void Log(Exception e) { }\n" +
                "}\n");
            var ctorRes = RunFix(ctorDir, true, allowSourceOnlyFallback: true);
            var ctorText = File.ReadAllText(ctorPath);
            bool ctorHasIoException =
                   ctorText.Contains("catch (System.UnauthorizedAccessException")
                || ctorText.Contains("catch (System.IO.IOException")
                || ctorText.Contains("catch (System.IO.DirectoryNotFoundException");
            bool t13 = ctorRes.Modified >= 1 && ctorHasIoException && !ctorText.Contains("catch (Exception ");
            L("--- Ctor.cs (after) ---");
            L(ctorText);
            L($"[13] 생성자 예외 수집: {(t13 ? "PASS" : "FAIL")} (Modified={ctorRes.Modified}, ioCatch={ctorHasIoException})");

            // ── [14] 직접 throw 수집 : try 내부 throw new InvalidOperationException 이 구체 catch 로 반영 ──
            var throwDir = Path.Combine(fixtureDir, "throwex");
            Directory.CreateDirectory(throwDir);
            var throwPath = Path.Combine(throwDir, "ThrowEx.cs");
            File.WriteAllText(throwPath,
                "using System;\n" +
                "class Te {\n" +
                "    void M(string s) {\n" +
                "        try { if (s == null) throw new InvalidOperationException(\"x\"); int.Parse(s); } catch (Exception ex) { Log(ex); }\n" +
                "    }\n" +
                "    void Log(Exception e) { }\n" +
                "}\n");
            var throwRes = RunFix(throwDir, true, allowSourceOnlyFallback: true);
            var throwText = File.ReadAllText(throwPath);
            bool t14 = throwRes.Modified >= 1 && throwText.Contains("catch (System.InvalidOperationException");
            L($"[14] 직접 throw 수집: {(t14 ? "PASS" : "FAIL")} (Modified={throwRes.Modified})");

            // ── [15] 람다 경계 : 람다 내부 int.Parse 는 수집 제외 → FormatException 부재, 파일 불변 ──
            var lambdaDir = Path.Combine(fixtureDir, "lambda");
            Directory.CreateDirectory(lambdaDir);
            var lambdaPath = Path.Combine(lambdaDir, "Lam.cs");
            File.WriteAllText(lambdaPath,
                "using System;\n" +
                "class Lm {\n" +
                "    void M(string s) {\n" +
                "        try { Func<string, int> f = t => int.Parse(t); GC.KeepAlive(f); } catch (Exception ex) { Log(ex); }\n" +
                "    }\n" +
                "    void Log(Exception e) { }\n" +
                "}\n");
            var lambdaBefore = File.ReadAllText(lambdaPath);
            var lambdaRes = RunFix(lambdaDir, true, allowSourceOnlyFallback: true);
            var lambdaText = File.ReadAllText(lambdaPath);
            bool lambdaUnchanged = lambdaText == lambdaBefore;
            bool t15 = !lambdaText.Contains("FormatException") && lambdaUnchanged;
            L($"[15] 람다 경계: {(t15 ? "PASS" : "FAIL")} (unchanged={lambdaUnchanged}, Skipped_Empty={lambdaRes.Skipped_Empty})");

            // ── [16] 중첩 try 보호블록 경계 : 외부는 내부 보호블록의 int.Parse 예외를 상속하지 않음 ──
            var nestGuardDir = Path.Combine(fixtureDir, "nestguard");
            Directory.CreateDirectory(nestGuardDir);
            var nestGuardPath = Path.Combine(nestGuardDir, "NestGuard.cs");
            File.WriteAllText(nestGuardPath,
                "using System;\n" +
                "class Ng {\n" +
                "    void M(string s) {\n" +
                "        try { try { int a = int.Parse(s); } catch (FormatException fe) { GC.KeepAlive(fe); } } catch (Exception ex) { Log(ex); }\n" +
                "    }\n" +
                "    void Log(Exception e) { }\n" +
                "}\n");
            var nestGuardBefore = File.ReadAllText(nestGuardPath);
            var nestGuardRes = RunFix(nestGuardDir, true, allowSourceOnlyFallback: true);
            var nestGuardText = File.ReadAllText(nestGuardPath);
            int outerBroadCount = System.Text.RegularExpressions.Regex.Matches(nestGuardText, @"catch \(Exception ex\)").Count;
            bool t16 = outerBroadCount == 1 && !nestGuardText.Contains("OverflowException") && nestGuardText == nestGuardBefore;
            L($"[16] 중첩 try 보호블록 경계: {(t16 ? "PASS" : "FAIL")} (broadCount={outerBroadCount}, noOverflow={!nestGuardText.Contains("OverflowException")}, unchanged={nestGuardText == nestGuardBefore})");

            // ── [17] 진단 지문 : 같은 CS0029 오류가 1→2 개로 늘면 신규 오류로 검출 (구 ID-set 로직은 미검출) ──
            var fpNet472 = @"C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.7.2\";
            var fpRefs = new[] { "mscorlib.dll", "System.dll", "System.Core.dll" }
                .Select(n => (MetadataReference)MetadataReference.CreateFromFile(Path.Combine(fpNet472, n)))
                .ToList();
            var fpComp1 = CSharpCompilation.Create("fp1")
                .WithOptions(new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary))
                .AddReferences(fpRefs)
                .AddSyntaxTrees(CSharpSyntaxTree.ParseText("class F1 { void M() { int x = \"a\"; } }"));
            var fpComp2 = CSharpCompilation.Create("fp2")
                .WithOptions(new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary))
                .AddReferences(fpRefs)
                .AddSyntaxTrees(CSharpSyntaxTree.ParseText("class F2 { void M() { int x = \"a\"; int y = \"b\"; } }"));
            var fpIntroduced = DiffIntroducedErrors(fpComp1.GetDiagnostics(), fpComp2.GetDiagnostics());
            var fpSame = DiffIntroducedErrors(fpComp1.GetDiagnostics(), fpComp1.GetDiagnostics());
            bool t17 = fpIntroduced.Count > 0 && fpSame.Count == 0;
            L($"[17] 진단 지문: {(t17 ? "PASS" : "FAIL")} (introduced={fpIntroduced.Count}, sameSame={fpSame.Count})");

            allPass = previewUnchanged && t1 && t2 && t3 && t4 && t5 && t6
                   && t7 && t8 && t9 && t10 && t11 && t12
                   && t13 && t14 && t15 && t16 && t17;
            L(allPass ? "SELFTEST-FIX PASS" : "SELFTEST-FIX FAIL");
        }
        catch (Exception ex)
        {
            L("SELFTEST-FIX EXCEPTION: " + ex);
            allPass = false;
            L("SELFTEST-FIX FAIL");
        }
        finally
        {
            try { Directory.Delete(fixtureDir, true); } catch { /* 정리 실패 무시 */ }
        }

        var text = sb.ToString();
        try
        {
            var resultPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "selftest-fix-result.txt");
            File.WriteAllText(resultPath, text);
        }
        catch { /* 파일 기록 실패 무시 */ }

        try { Console.WriteLine(text); } catch { /* 콘솔 없을 수 있음 */ }

        return allPass ? 0 : 1;
    }
}
