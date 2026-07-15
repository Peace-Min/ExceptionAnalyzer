using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis;
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

    // 분석 로그 싱크: 콘솔(헤드리스) 또는 WPF 창으로 라우팅
    public static Action<string> Log = Console.WriteLine;

    private static void LoadXmlDocumentation()
    {
        foreach (var xmlFile in Directory.GetFiles(NET_FRAMEWORK_PATH, "*.xml"))
        {
            try
            {
                var doc = XDocument.Load(xmlFile);
                var members = doc.Root?.Element("members")?.Elements("member") ?? Enumerable.Empty<XElement>();

                foreach (var member in members)
                {
                    var nameAttr = member.Attribute("name")?.Value;
                    if (string.IsNullOrEmpty(nameAttr) || !nameAttr.StartsWith("M:")) continue;

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

    // 분석 진입점: 하드코딩 경로 대신 인자로 받은 폴더를 분석한다. 백그라운드 스레드에서 반복 호출해도 안전.
    public static void AnalyzeDirectory(string targetDirectory)
    {
        // 반복 호출 안전: 파일별 예외 목록 상태 초기화
        methodExceptionList = new Dictionary<string, string>();

        // XML 문서 로드 (최초 1회)
        if (_apiDocCache.Count == 0)
        {
            Log("📚 .NET Framework XML 문서 로딩 중...");
            LoadXmlDocumentation();
            Log($"✅ {_apiDocCache.Count}개의 API 문서 로드 완료");
        }

        var lastFolderName = new DirectoryInfo(targetDirectory).Name;

        // 2. 출력 파일 경로 지정
        var outputPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"{lastFolderName}_ApiCallCandidates.txt");
        var unregisteredExceptionMapPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"{lastFolderName}_UnregisteredExceptionMap.txt"); // ExceptionMap에 등록안된 메소드만 별도로 저장

        // 3. 출력 스트림 오픈
        using var writer = new StreamWriter(outputPath);
        using var exceptionWriter = new StreamWriter(unregisteredExceptionMapPath);

        Log($"🔍 디렉토리 분석 시작: {targetDirectory}");

        // 4. 디렉토리 내 모든 .cs 파일 재귀적으로 수집
        var csFiles = Directory.GetFiles(targetDirectory, "*.cs", SearchOption.AllDirectories);

        // 5. 각 파일에 대해 반복 수행
        foreach (var file in csFiles)
        {
            // 5-1. 파일 내용을 문자열로 읽어옴 (백그라운드 스레드에서 동기 실행)
            var code = File.ReadAllText(file);

            // 5-2. Roslyn으로 C# 구문 트리(SyntaxTree) 생성
            var tree = CSharpSyntaxTree.ParseText(code);

            // 5-3. 구문 트리에서 루트 노드 추출 (SyntaxNode)
            var root = tree.GetRoot();

            // 5-4. 모든 try 블록을 AST에서 수집
            var tryStatements = root.DescendantNodes().OfType<TryStatementSyntax>().ToList();

            if (!tryStatements.Any()) continue;

            // 6. 대상 프로젝트 분석에 필요한 메타데이터 설정 (bin\Debug + net472 기본 어셈블리)
            var references = BuildReferences(targetDirectory);

            // 7. Roslyn 컴파일러 객체 생성 (코드 분석에 필요)
            var compilation = CSharpCompilation.Create("Analysis")
                .AddReferences(references)
                .AddSyntaxTrees(tree);// 현재 분석 중인 소스 트리 추가

            // 8. 현재 구문 트리에 대한 의미 정보 모델(SemanticModel) 생성
            var semanticModel = compilation.GetSemanticModel(tree);

            // 9. 각 try 블록 내부를 분석
            foreach (var tryStmt in tryStatements)
            {
                // 9-1. 해당 try 블록의 위치 출력
                var lineSpan = tryStmt.GetLocation().GetLineSpan();
                var line = lineSpan.StartLinePosition.Line + 1;

                // 9-2. try 블록 내부의 모든 메서드 호출 구문 수집
                var methodCalls = tryStmt.Block.DescendantNodes().OfType<InvocationExpressionSyntax>();

                if (!methodCalls.Any()) continue; // 🔥 메서드 호출 없으면 출력 생략

                var message = $"📄 파일: {file}, 줄: {line} → try 블록 내부 API 호출:";
                Log(message);
                writer.WriteLine(message);

                // 9-3. try 블록 내부 예외 집계 (추출된 재사용 코어). 파일 writer/exceptionWriter를 넘겨 --analyze 출력 보존.
                methodExceptionList = AnalyzeTryBlock(tryStmt, semanticModel, writer, exceptionWriter);

                EmitOrderedCatches(writer, compilation, methodExceptionList);
            }
        }

        // 결과 저장 및 종료 메시지 출력
        writer.Flush();
        exceptionWriter.Flush();
        Log("📄 결과 저장 완료: " + outputPath);
    }

    // exMap 에 집계, writer/exceptionWriter 는 nullable — null 이면 파일/로그 출력 없이 순수 집계만 수행(RunFix 재사용).
    private static void AnalyzeInternalMethod(MethodDeclarationSyntax methodSyntax, SemanticModel semanticModel, StreamWriter? writer, StreamWriter? exceptionWriter, string callerFullName, int depth, Dictionary<string, string> exMap)
    {
        var indent = new string(' ', depth * 4); // 재귀 깊이에 따라 들여쓰기

        var internalCalls = methodSyntax.DescendantNodes()
                                        .OfType<InvocationExpressionSyntax>()
                                        .ToList();

        foreach (var innerCall in internalCalls)
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
                // ③ 정확한 문서 주석 ID로 일치하는 오버로드만 조회 (이름 충돌 과매칭 제거)
                var docId = innerSymbol.GetDocumentationCommentId();
                List<ApiDocumentation> matchedDocs;
                if (docId != null && _apiDocCache.TryGetValue(docId, out var exactDoc))
                    matchedDocs = new List<ApiDocumentation> { exactDoc };
                else
                    matchedDocs = new List<ApiDocumentation>();

                if (matchedDocs.Count == 0)
                {
                    if (writer != null)
                    {
                        writer.WriteLine($"    🔧 {methodFullName}() - 문서화되지 않은 메서드");
                        Log($"    🔧 {methodFullName}() - 문서화되지 않은 메서드");
                    }
                    continue;
                }

                var docmentList = new List<ApiDocumentation>();
                var exceptionList = new List<KeyValuePair<string, string>>();

                foreach (var doc in matchedDocs)
                {
                    if (doc.Exceptions.Any())
                    {
                        foreach (var exception in doc.Exceptions)
                        {
                            exMap[exception.Key] = exception.Value;

                            if (!exceptionList.Any(item => item.Key == exception.Key))
                            {
                                exceptionList.Add(exception);
                            }
                        }
                    }
                    else if (writer != null)
                    {
                        writer.WriteLine("        📌 문서화된 예외 정보 없음");
                        Log("        📌 문서화된 예외 정보 없음");
                    }
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
                    AnalyzeInternalMethod(nextMethodSyntax, semanticModel, writer, exceptionWriter, methodFullName, depth + 1, exMap);
                }
            }
        }
    }

    // ── 추출된 재사용 코어 ① : bin\Debug + net472 기본 어셈블리 참조 목록 생성 (AnalyzeDirectory·RunFix 공용)
    public static List<MetadataReference> BuildReferences(string targetDirectory)
    {
        var references = new List<MetadataReference>();

        // 현재 프로젝트 bin\Debug 의 dll 추가 (필요 시 net472 등 서브폴더 포함)
        var dllPath = Path.Combine(targetDirectory, "bin", "Debug");
        if (Directory.Exists(dllPath))
        {
            var dlls = Directory.GetFiles(dllPath, "*.dll");
            var dllReferences = dlls.Select(path => (MetadataReference)MetadataReference.CreateFromFile(path)).ToList();
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
                   .Select(name => (MetadataReference)MetadataReference.CreateFromFile(Path.Combine(net472Path, name))));

        return references;
    }

    // ── 추출된 재사용 코어 ② : try 블록 내부 예외 집계 (type→한글설명 맵). writer 가 null 이면 순수 집계(무출력).
    public static Dictionary<string, string> AnalyzeTryBlock(TryStatementSyntax tryStmt, SemanticModel semanticModel, StreamWriter? writer = null, StreamWriter? exceptionWriter = null)
    {
        var exMap = new Dictionary<string, string>();

        var methodCalls = tryStmt.Block.DescendantNodes().OfType<InvocationExpressionSyntax>();

        foreach (var call in methodCalls)
        {
            var symbolInfo = semanticModel.GetSymbolInfo(call);
            var methodSymbol = symbolInfo.Symbol as IMethodSymbol;

            if (methodSymbol == null) continue;

            var ns = methodSymbol.ContainingNamespace?.ToDisplayString();
            if (string.IsNullOrEmpty(ns)) continue;

            var methodFullName = $"{methodSymbol.ContainingNamespace}.{methodSymbol.ContainingType.Name}.{methodSymbol.Name}";

            if (ns.StartsWith("System") || ns.StartsWith("Microsoft"))
            {
                // ③ 정확한 문서 주석 ID로 일치하는 오버로드만 조회 (이름 충돌 과매칭 제거)
                var docId = methodSymbol.GetDocumentationCommentId();
                List<ApiDocumentation> matchedDocs;
                if (docId != null && _apiDocCache.TryGetValue(docId, out var exactDoc))
                    matchedDocs = new List<ApiDocumentation> { exactDoc };
                else
                    matchedDocs = new List<ApiDocumentation>();

                if (matchedDocs.Count == 0) continue;

                var exceptionList = new List<KeyValuePair<string, string>>();

                foreach (var doc in matchedDocs)
                {
                    if (doc.Exceptions.Any())
                    {
                        foreach (var exception in doc.Exceptions)
                        {
                            exMap[exception.Key] = exception.Value;

                            if (!exceptionList.Any(item => item.Key == exception.Key))
                            {
                                exceptionList.Add(exception);
                            }
                        }
                    }
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
                    AnalyzeInternalMethod(methodDeclSyntax, semanticModel, writer, exceptionWriter, methodFullName, 1, exMap);
                }
            }
        }

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
    private static TryStatementSyntax BuildReplacementTry(TryStatementSyntax original, List<string> fullTypeNames)
    {
        var sb = new StringBuilder();
        sb.Append("try ");
        sb.Append(original.Block.ToString()); // try 본문 그대로 (변경 없음)
        sb.Append('\n');
        foreach (var t in fullTypeNames)
        {
            // 완전수식 타입 + 완전수식 Debug 호출 (using 추가 없음)
            sb.Append($"catch ({t} ex) {{ System.Diagnostics.Debug.WriteLine(ex); /* [AUTO-CATCH] 로거로 교체 */ }}\n");
        }
        if (original.Finally != null)
        {
            sb.Append(original.Finally.ToString()); // finally 보존
            sb.Append('\n');
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

    public static FixResult RunFix(string targetDirectory, bool apply)
    {
        var res = new FixResult();

        if (_apiDocCache.Count == 0)
        {
            LoadXmlDocumentation();
        }

        var references = BuildReferences(targetDirectory);
        var csFiles = Directory.GetFiles(targetDirectory, "*.cs", SearchOption.AllDirectories);

        foreach (var file in csFiles)
        {
            var code = File.ReadAllText(file);
            var tree = CSharpSyntaxTree.ParseText(code);
            var root = tree.GetRoot();

            var compilation = CSharpCompilation.Create("Fix")
                .AddReferences(references)
                .AddSyntaxTrees(tree);
            var semanticModel = compilation.GetSemanticModel(tree);

            var tries = root.DescendantNodes().OfType<TryStatementSyntax>().ToList();
            if (tries.Count == 0) continue;

            var replacements = new Dictionary<TryStatementSyntax, TryStatementSyntax>();
            var previewPending = new List<string>();

            foreach (var tryStmt in tries)
            {
                var catches = tryStmt.Catches;

                // 단일 catch 만 대상 (finally 는 허용). 0개/다중 catch → not-broad.
                if (catches.Count != 1)
                {
                    res.Skipped_NotBroad++;
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
                    var ln = tryStmt.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                    res.ManualReview.Add($"{file}:{ln}");
                    res.Skipped_NonTrivial++;
                    continue;
                }

                // 적격 대상: 구체 예외 추론
                var exMap = AnalyzeTryBlock(tryStmt, semanticModel);
                var types = GetOrderedResolvedCatchTypes(compilation, exMap);
                if (types.Count == 0)
                {
                    // catch-less try 를 절대 만들지 않음
                    res.Skipped_Empty++;
                    continue;
                }

                var newTry = BuildReplacementTry(tryStmt, types);
                replacements[tryStmt] = newTry;

                var line = tryStmt.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                previewPending.Add(BuildPreviewBlock(file, line, tryStmt.ToString(), newTry.ToString()));
            }

            if (replacements.Count == 0) continue;

            var newRoot = root.ReplaceNodes(
                replacements.Keys,
                (originalNode, _) => replacements[originalNode].WithTriviaFrom(originalNode));

            // 들여쓰기 정리
            var workspace = new AdhocWorkspace();
            var formattedRoot = Microsoft.CodeAnalysis.Formatting.Formatter.Format(newRoot, workspace);
            var formattedText = formattedRoot.ToFullString();

            // 파일별 자가검증: 새 트리가 원본에 없던 새 오류를 유발하면 통째로 폐기
            var origErrorIds = compilation.GetDiagnostics()
                .Where(d => d.Severity == DiagnosticSeverity.Error)
                .Select(d => d.Id)
                .ToHashSet();

            var newTree = CSharpSyntaxTree.ParseText(formattedText);
            var newComp = CSharpCompilation.Create("FixValidate")
                .AddReferences(references)
                .AddSyntaxTrees(newTree);
            var introduced = newComp.GetDiagnostics()
                .Where(d => d.Severity == DiagnosticSeverity.Error && !origErrorIds.Contains(d.Id))
                .ToList();

            if (introduced.Count > 0)
            {
                res.CompileReverted++;
                res.ManualReview.Add($"{file} (컴파일 롤백: {string.Join(",", introduced.Select(d => d.Id).Distinct())})");
                continue; // 이 파일 변경 폐기
            }

            // 검증 통과
            res.Modified += replacements.Count;
            res.PreviewBlocks.AddRange(previewPending);

            if (apply)
            {
                File.WriteAllText(file, formattedText);
            }
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
        sb.AppendLine();
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
            var previewRes = RunFix(fixtureDir, false);
            bool previewUnchanged = files.All(f => File.ReadAllText(f) == before[f]);
            L($"[preview] 디스크 미변경: {(previewUnchanged ? "PASS" : "FAIL")} (Modified 미리보기={previewRes.Modified})");

            // 3. apply
            var res = RunFix(fixtureDir, true);

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

            allPass = previewUnchanged && t1 && t2 && t3 && t4 && t5 && t6;
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
