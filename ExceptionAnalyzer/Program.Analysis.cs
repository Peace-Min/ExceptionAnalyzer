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

internal partial class Program
{
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
}
