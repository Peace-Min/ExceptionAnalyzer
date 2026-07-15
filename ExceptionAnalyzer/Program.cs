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

            // 6. 대상 프로젝트 분석에 필요한 메타데이터 설정
            var references = new List<PortableExecutableReference>();

            // 6-1. 현재 프로젝트에서 dll 폴더 경로 설정
            var dllPath = Path.Combine(targetDirectory, "bin", "Debug"); // 필요 시 net472 등 서브폴더 포함
            if (Directory.Exists(dllPath))
            {
                //Console.WriteLine("⚠️ bin 폴더가 존재하지 않습니다. 먼저 빌드가 완료되어야 합니다.");
                var dlls = Directory.GetFiles(dllPath, "*.dll");
                var dllReferences = dlls.Select(path => MetadataReference.CreateFromFile(path)).ToList();
                references.AddRange(dllReferences);
            }

            // ※ 분석 대상 프로젝트에 맞춰서 기본 어셈블리 설정 필요 ※

            // ✅ .NET Framework 4.7.2의 필수 기본 어셈블리를 명시적으로 참조 추가
            // bin\Debug에는 포함되지 않는 GAC(Global Assembly Cache) 기반 DLL들을 수동 지정해야 함
            // 이들 어셈블리는 기본 API (예: System.Math, System.Linq.Enumerable 등)의 정의를 포함함
            // 누락 시 Roslyn 분석 중 일부 System 메서드(Symbol)가 null로 인식되어 API 추적 실패 가능성 있음
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
                       .Select(name => MetadataReference.CreateFromFile(Path.Combine(net472Path, name))));

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


                // 9-3. 각 호출에 대해 의미 정보 추출
                methodExceptionList = new Dictionary<string, string>();
                foreach (var call in methodCalls)
                {
                    var symbolInfo = semanticModel.GetSymbolInfo(call);
                    var methodSymbol = symbolInfo.Symbol as IMethodSymbol;

                    if (methodSymbol == null) continue;

                    var ns = methodSymbol.ContainingNamespace?.ToDisplayString();
                    if (string.IsNullOrEmpty(ns)) continue;

                    var methodName = methodSymbol.Name;
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

                        if (matchedDocs.Count == 0)
                        {

                            //writer.WriteLine($"    🔧 {methodFullName}() - 예외가 없는 메서드");
                            //Console.WriteLine($"    🔧 {methodFullName}() - 예외가 없는 메서드");
                            continue;
                        }

                        var docmentList = new List<ApiDocumentation>();
                        var exceptionList = new List<KeyValuePair<string, string>>();

                        foreach (var doc in matchedDocs)
                        {

                            //writer.WriteLine($"    🔧 {doc.MethodName}()");
                            //Console.WriteLine($"    🔧 {doc.MethodName}()");

                            if (doc.Exceptions.Any())
                            {
                                foreach (var exception in doc.Exceptions)
                                {
                                    methodExceptionList[exception.Key] = exception.Value;

                                    if (!exceptionList.Any(item => item.Key == exception.Key))
                                    {
                                        exceptionList.Add(exception);
                                    }
                                }
                            }
                        }


                        foreach (var exception in exceptionList)
                        {
                            writer.WriteLine($"        → 예상 예외: {exception.Key}");
                            Log($"        → 예상 예외: {exception.Key}");
                        }
                    }
                    else
                    {
                        var nonFrameworkCall = $"프레임워크에 등록되지 않은 API : {methodSymbol.ContainingNamespace}.{methodSymbol.ContainingType.Name}.{methodSymbol.Name}";
                        writer.WriteLine($"    🔧 {nonFrameworkCall}()");
                        Log($"    🔧 {nonFrameworkCall}()");

                        // 해당 메서드 정의 위치를 찾음 (재귀 분석용)
                        var methodDeclSyntax = methodSymbol.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() as MethodDeclarationSyntax;

                        if (methodDeclSyntax != null)
                        {
                            AnalyzeInternalMethod(methodDeclSyntax, semanticModel, writer, exceptionWriter, methodFullName, 1);
                        }
                    }

                }

                EmitOrderedCatches(writer, compilation, methodExceptionList);
            }
        }

        // 결과 저장 및 종료 메시지 출력
        writer.Flush();
        exceptionWriter.Flush();
        Log("📄 결과 저장 완료: " + outputPath);
    }

    private static void AnalyzeInternalMethod(MethodDeclarationSyntax methodSyntax, SemanticModel semanticModel, StreamWriter writer, StreamWriter exceptionWriter, string callerFullName, int depth)
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

            writer.WriteLine($"{indent}🔄 내부 호출: {methodFullName}()");
            Log($"{indent}🔄 내부 호출: {methodFullName}()");

            // 프레임워크 API 예외 추론
            var ns = innerSymbol.ContainingNamespace?.ToDisplayString();
            if (ns.StartsWith("System") || ns.StartsWith("Microsoft"))
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

                    writer.WriteLine($"    🔧 {methodFullName}() - 문서화되지 않은 메서드");
                    Log($"    🔧 {methodFullName}() - 문서화되지 않은 메서드");
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
                            methodExceptionList[exception.Key] = exception.Value;

                            if (!exceptionList.Any(item => item.Key == exception.Key))
                            {
                                exceptionList.Add(exception);
                            }
                        }
                    }
                    else
                    {
                        writer.WriteLine("        📌 문서화된 예외 정보 없음");
                        Log("        📌 문서화된 예외 정보 없음");
                    }
                }

                foreach (var exception in exceptionList)
                {
                    writer.WriteLine($"        → 예상 예외: {exception.Key}");
                    Log($"        → 예상 예외: {exception.Key}");
                }
            }
            else
            {
                // 중첩 사용자 정의 메서드면 재귀 호출
                var nextMethodSyntax = innerSymbol.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() as MethodDeclarationSyntax;
                if (nextMethodSyntax != null && depth < 5) // 최대 재귀 제한
                {
                    AnalyzeInternalMethod(nextMethodSyntax, semanticModel, writer, exceptionWriter, methodFullName, depth + 1);
                }
            }
        }
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

        // resolve each type to a symbol via the same compilation
        int Depth(INamedTypeSymbol s) { int d = 0; var t = s; while (t != null) { d++; t = t.BaseType; } return d; }
        var resolved = items
            .Select(kv => new { Name = kv.Key, Desc = kv.Value, Sym = compilation.GetTypeByMetadataName(kv.Key) })
            .Where(x => x.Sym != null)
            // ① derived-before-base: single-inheritance ⇒ a subtype is strictly deeper ⇒ depth DESC is a valid catch order
            .OrderByDescending(x => Depth(x.Sym!))
            .ThenBy(x => x.Name, StringComparer.Ordinal)
            .ToList();
        var unresolved = items
            .Where(kv => compilation.GetTypeByMetadataName(kv.Key) == null)
            .Select(kv => kv.Key)
            .ToList();

        // ⑤ Roslyn self-compile validation over the RESOLVED, ordered set
        var orderedNames = resolved.Select(x => x.Name).ToList();
        var validation = ValidateCatchOrder(orderedNames, compilation);

        Emit(writer, "🐙 catch 권장 순서 (파생 → 기반, Exception 제외):");
        int i = 1;
        foreach (var x in resolved)
            Emit(writer, $"    {i++}. {ShortTypeName(x.Name)} : {x.Desc}");
        if (unresolved.Count > 0)
            Emit(writer, $"    ⚠️ 해석 불가(수동 확인 — 외부 라이브러리/미빌드): {string.Join(", ", unresolved.Select(ShortTypeName))}");
        Emit(writer, validation);

        Emit(writer, "── 붙여넣기용 스켈레톤 ──────────────────────");
        foreach (var x in resolved)
            Emit(writer, $"catch ({ShortTypeName(x.Name)} ex) {{ /* {x.Desc} */ }}");
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
}
