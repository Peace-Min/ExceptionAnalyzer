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
        internal List<PendingWrite> PendingWrites = new List<PendingWrite>();
        // P1-11: 완전성(completeness) 추적 — 워크스페이스 로드 실패/건너뛴 문서가 있으면 부분 수행.
        public List<string> WorkspaceFailures = new List<string>();
        public List<string> CoverageWarnings = new List<string>();
        // 권고1: 커버리지 갭은 fallback(원본 broad catch)으로 런타임 안전 → 비차단 정보성.
        // 무결성 위협(파일 미컴파일/source-only 정책 등)만 apply 를 차단한다.
        public List<string> IntegrityFailures = new List<string>();
        public int SkippedDocuments;
        // 파일별 best-effort 게이팅: baseline 컴파일 오류로 '적용'에서 제외된 파일 수(REPORTING 카운터).
        public int SkippedIntegrityFiles;
        // source-only(.sln/MSBuildWorkspace 없이) 진단 전용 모드 여부 — 프로덕션에서는 절대 파일을 쓰지 않는다.
        public bool SourceOnlyDiagnostic;
        // 권고2: 저장 실패를 성공으로 오보하지 않도록 별도 플래그로 추적.
        public bool ApplyFailed;
        public int AppliedFileCount;
        // IsComplete 는 이제 '보고' 플래그(= exit code 결정). apply 게이트가 아니다 — 클린 파일은 PARTIAL 이어도 적용된다.
        public bool IsComplete => WorkspaceFailures.Count == 0 && IntegrityFailures.Count == 0 && SkippedDocuments == 0 && SkippedIntegrityFiles == 0;
        public bool HasCoverageGaps => CoverageWarnings.Count > 0;

        public void AddCoverageWarning(string message)
        {
            if (!CoverageWarnings.Contains(message, StringComparer.OrdinalIgnoreCase))
                CoverageWarnings.Add(message);
        }

        public void AddIntegrityFailure(string m)
        {
            if (!IntegrityFailures.Contains(m, StringComparer.OrdinalIgnoreCase))
                IntegrityFailures.Add(m);
        }
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
    private static TryStatementSyntax BuildReplacementTry(TryStatementSyntax original, CatchClauseSyntax originalCatch, List<string> fullTypeNames, string eol)
    {
        var originalExceptionName = originalCatch.Declaration?.Identifier.ValueText;
        var generatedExceptionName = string.IsNullOrWhiteSpace(originalExceptionName) ? "ex" : "__autoCatchEx";

        string ReplacementBody()
        {
            if (originalCatch.Block.Statements.Count == 0)
                return "{ /* [AUTO-CATCH] 원본 빈 catch */ }";

            if (originalCatch.Declaration == null || string.IsNullOrWhiteSpace(originalExceptionName))
                return originalCatch.Block.ToString();

            var originalTypeText = originalCatch.Declaration.Type.ToString();
            var bodyText = originalCatch.Block.ToString();
            var open = bodyText.IndexOf('{');
            var close = bodyText.LastIndexOf('}');
            if (open < 0 || close <= open) return bodyText;

            var inner = bodyText.Substring(open + 1, close - open - 1);
            return "{" + eol
                + $"    {originalTypeText} {originalExceptionName} = {generatedExceptionName};"
                + inner
                + eol
                + "}";
        }

        var replacementBody = ReplacementBody();

        var sb = new StringBuilder();
        sb.Append("try ");
        sb.Append(original.Block.ToString()); // try 본문 그대로 (변경 없음)
        sb.Append(eol);
        foreach (var t in fullTypeNames)
        {
            // 완전수식 타입 + 기존 안전 catch 본문 보존. 빈 catch 는 동작 변경 없이 마커 주석만 넣는다.
            sb.Append($"catch ({t} {generatedExceptionName}) ");
            sb.Append(replacementBody).Append(eol);
        }
        // 정적 추론은 문서 미기재/암시적 연산/프로젝트 간 전파를 완전히 증명하지 못한다.
        // 원본 broad catch 를 fallback 으로 남겨 미추론 예외의 런타임 동작을 보존한다.
        sb.Append(originalCatch.ToString()).Append(eol);
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

    private static void AtomicWriteAllText(string file, string text, Encoding enc)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(file));
        if (string.IsNullOrEmpty(directory))
        {
            File.WriteAllText(file, text, enc);
            return;
        }

        var tempFile = Path.Combine(directory, "." + Path.GetFileName(file) + "." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            File.WriteAllText(tempFile, text, enc);
            if (File.Exists(file))
            {
                File.Replace(tempFile, file, null);
            }
            else
            {
                File.Move(tempFile, file);
            }
        }
        finally
        {
            try
            {
                if (File.Exists(tempFile)) File.Delete(tempFile);
            }
            catch { /* best-effort temp cleanup */ }
        }
    }

    private static void AtomicWriteAllBytes(string file, byte[] bytes)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(file));
        if (string.IsNullOrEmpty(directory))
        {
            File.WriteAllBytes(file, bytes);
            return;
        }

        var tempFile = Path.Combine(directory, "." + Path.GetFileName(file) + "." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            File.WriteAllBytes(tempFile, bytes);
            if (File.Exists(file))
                File.Replace(tempFile, file, null);
            else
                File.Move(tempFile, file);
        }
        finally
        {
            try
            {
                if (File.Exists(tempFile)) File.Delete(tempFile);
            }
            catch { /* best-effort temp cleanup */ }
        }
    }

    // internal: selftest/xunit 테스트 시임(테스트에서 직접 호출). 쓰기 메커니즘·롤백 의미는 불변.
    internal static void ApplyPendingWrites(FixResult res)
    {
        if (res.PendingWrites.Count == 0) return;

        // 권고3(G6): content-hash TOCTOU 가드 — scan 시점에 읽어둔 원본 바이트와
        // 지금 디스크 바이트를 대조해, 스캔 이후 외부 수정이 있으면 배치 전체를 중단(all-or-nothing).
        foreach (var write in res.PendingWrites)
        {
            byte[] current;
            try { current = File.ReadAllBytes(write.File); }
            catch (Exception ex) { res.ApplyFailed = true; res.ManualReview.Add($"{write.File} (적용 전 재확인 실패: {ex.GetType().Name})"); return; }
            if (!current.AsSpan().SequenceEqual(write.ExpectedOriginalBytes))
            {
                res.ApplyFailed = true;
                res.ManualReview.Add($"{write.File} (외부 수정 감지 — 스캔 이후 파일이 변경됨, 배치 전체 적용 중단)");
                return; // write nothing (all-or-nothing)
            }
        }

        var originals = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var write in res.PendingWrites)
        {
            if (File.Exists(write.File) && !originals.ContainsKey(write.File))
                originals[write.File] = File.ReadAllBytes(write.File);
        }

        try
        {
            foreach (var write in res.PendingWrites)
                AtomicWriteAllText(write.File, write.Text, write.Encoding);
            res.AppliedFileCount = res.PendingWrites.Count;
        }
        catch (Exception ex)
        {
            // 권고2: 쓰기 실패는 CompileReverted(컴파일 되돌림)가 아니라 ApplyFailed 로 보고.
            res.ApplyFailed = true;
            res.ManualReview.Add($"batch apply rollback: {ex.GetType().Name} {ex.Message}");
            foreach (var original in originals)
            {
                try { AtomicWriteAllBytes(original.Key, original.Value); }
                catch (Exception restoreEx) { res.ManualReview.Add($"{original.Key} (rollback 실패: {restoreEx.GetType().Name} {restoreEx.Message})"); }
            }
        }
    }

    internal sealed class PendingWrite
    {
        public PendingWrite(string file, string text, Encoding encoding, byte[] expectedOriginalBytes)
        {
            File = file;
            Text = text;
            Encoding = encoding;
            ExpectedOriginalBytes = expectedOriginalBytes;
        }

        public string File { get; }
        public string Text { get; }
        public Encoding Encoding { get; }
        // 권고3: scan 시점에 읽은 원본 바이트(쓰기는 지연되므로 이 시점 파일은 여전히 원본).
        public byte[] ExpectedOriginalBytes { get; }
    }

    private static bool IsFrameworkNamespace(string? ns)
    {
        return ns == "System"
            || ns?.StartsWith("System.", StringComparison.Ordinal) == true
            || ns == "Microsoft"
            || ns?.StartsWith("Microsoft.", StringComparison.Ordinal) == true;
    }

    private static string SymbolDisplay(ISymbol symbol)
    {
        return symbol.ToDisplayString(SymbolDisplayFormat.CSharpErrorMessageFormat);
    }

    private static void AddUnsupportedExecutionCoverageWarnings(FixResult res, string file, int line, TryStatementSyntax tryStmt, SemanticModel semanticModel)
    {
        var nodes = tryStmt.Block.DescendantNodes(n => n is not AnonymousFunctionExpressionSyntax and not LocalFunctionStatementSyntax);

        foreach (var assign in nodes.OfType<AssignmentExpressionSyntax>())
        {
            var leftSymbol = semanticModel.GetSymbolInfo(assign.Left).Symbol;
            if (leftSymbol is IPropertySymbol or IEventSymbol)
                res.AddCoverageWarning($"{file}:{line} — 미지원 실행 지점: property/event assignment 예외 전파 미분석: {assign}");
        }

        foreach (var unary in nodes.OfType<PrefixUnaryExpressionSyntax>())
        {
            var symbol = semanticModel.GetSymbolInfo(unary).Symbol;
            if (symbol is IMethodSymbol method && method.MethodKind == MethodKind.UserDefinedOperator)
                res.AddCoverageWarning($"{file}:{line} — 미지원 실행 지점: user-defined operator 예외 전파 미분석: {SymbolDisplay(method)}");
        }

        foreach (var unary in nodes.OfType<PostfixUnaryExpressionSyntax>())
        {
            var symbol = semanticModel.GetSymbolInfo(unary).Symbol;
            if (symbol is IMethodSymbol method && method.MethodKind == MethodKind.UserDefinedOperator)
                res.AddCoverageWarning($"{file}:{line} — 미지원 실행 지점: user-defined operator 예외 전파 미분석: {SymbolDisplay(method)}");
        }

        foreach (var binary in nodes.OfType<BinaryExpressionSyntax>())
        {
            var symbol = semanticModel.GetSymbolInfo(binary).Symbol;
            if (symbol is IMethodSymbol method && method.MethodKind == MethodKind.UserDefinedOperator)
                res.AddCoverageWarning($"{file}:{line} — 미지원 실행 지점: user-defined operator 예외 전파 미분석: {SymbolDisplay(method)}");
        }

        foreach (var cast in nodes.OfType<CastExpressionSyntax>())
        {
            var conversion = semanticModel.GetConversion(cast.Expression);
            if (conversion.IsUserDefined)
                res.AddCoverageWarning($"{file}:{line} — 미지원 실행 지점: user-defined conversion 예외 전파 미분석: {cast}");
        }

        foreach (var awaitExpression in nodes.OfType<AwaitExpressionSyntax>())
            res.AddCoverageWarning($"{file}:{line} — 미지원 실행 지점: await 상태머신/awaiter 예외 전파 미분석: {awaitExpression}");

        foreach (var foreachStatement in nodes.OfType<ForEachStatementSyntax>())
            res.AddCoverageWarning($"{file}:{line} — 미지원 실행 지점: foreach enumerator/Dispose 예외 전파 미분석: {foreachStatement.Expression}");

        foreach (var usingStatement in nodes.OfType<UsingStatementSyntax>())
            res.AddCoverageWarning($"{file}:{line} — 미지원 실행 지점: using Dispose 예외 전파 미분석");

        foreach (var query in nodes.OfType<QueryExpressionSyntax>())
            res.AddCoverageWarning($"{file}:{line} — 미지원 실행 지점: query expression LINQ 호출 예외 전파 미분석: {query.FromClause.Identifier.ValueText}");
    }

    private static void CollectCoverageWarnings(FixResult res, string file, int line, TryStatementSyntax tryStmt, SemanticModel semanticModel, CSharpCompilation compilation, IReadOnlyDictionary<SyntaxTree, SemanticContext>? semanticContexts, IReadOnlyDictionary<string, MethodContext>? methodContexts)
    {
        AddUnsupportedExecutionCoverageWarnings(res, file, line, tryStmt, semanticModel);

        var invocations = new List<InvocationExpressionSyntax>();
        var creations = new List<BaseObjectCreationExpressionSyntax>();
        var thrownExpressions = new List<ExpressionSyntax>();
        var accessExpressions = new List<ExpressionSyntax>();
        CollectThrowCapable(tryStmt.Block, invocations, creations, thrownExpressions, accessExpressions);

        foreach (var call in invocations)
        {
            var symbolInfo = semanticModel.GetSymbolInfo(call);
            var methodSymbol = symbolInfo.Symbol as IMethodSymbol
                            ?? symbolInfo.CandidateSymbols.FirstOrDefault() as IMethodSymbol;
            if (methodSymbol == null)
            {
                res.AddCoverageWarning($"{file}:{line} — 호출 심볼 해석 실패: {call}");
                continue;
            }

            var ns = methodSymbol.ContainingNamespace?.ToDisplayString();
            if (IsFrameworkNamespace(ns))
            {
                if (LookupDocumentedExceptions(methodSymbol) == null)
                    res.AddCoverageWarning($"{file}:{line} — framework API 예외 문서 없음: {SymbolDisplay(methodSymbol)}");
                continue;
            }

            var methodContext = ResolveMethodContext(methodSymbol, compilation, semanticModel, semanticContexts, methodContexts);
            if (methodContext == null)
            {
                res.AddCoverageWarning($"{file}:{line} — 외부/라이브러리 호출 예외 전파 미분석: {SymbolDisplay(methodSymbol)}");
                continue;
            }
        }

        foreach (var creation in creations)
        {
            var ctorSymbol = semanticModel.GetSymbolInfo(creation).Symbol as IMethodSymbol;
            if (ctorSymbol == null)
            {
                res.AddCoverageWarning($"{file}:{line} — 생성자 심볼 해석 실패: {creation}");
                continue;
            }

            var ns = ctorSymbol.ContainingNamespace?.ToDisplayString();
            if (IsFrameworkNamespace(ns))
            {
                if (LookupDocumentedExceptions(ctorSymbol) == null)
                    res.AddCoverageWarning($"{file}:{line} — framework 생성자 예외 문서 없음: {SymbolDisplay(ctorSymbol)}");
            }
            else
            {
                res.AddCoverageWarning($"{file}:{line} — 사용자/외부 생성자 예외 전파 미분석: {SymbolDisplay(ctorSymbol)}");
            }
        }

        foreach (var expr in thrownExpressions)
        {
            if (semanticModel.GetTypeInfo(expr).Type == null)
                res.AddCoverageWarning($"{file}:{line} — 직접 throw 타입 해석 실패: {expr}");
        }

        foreach (var access in accessExpressions)
        {
            var propSymbol = semanticModel.GetSymbolInfo(access).Symbol as IPropertySymbol;
            if (propSymbol == null) continue;

            var ns = propSymbol.ContainingNamespace?.ToDisplayString();
            if (IsFrameworkNamespace(ns) && LookupDocumentedExceptions(propSymbol) == null)
                res.AddCoverageWarning($"{file}:{line} — framework 속성/인덱서 예외 문서 없음: {SymbolDisplay(propSymbol)}");
            else if (!IsFrameworkNamespace(ns))
                res.AddCoverageWarning($"{file}:{line} — 사용자/외부 속성/인덱서 예외 전파 미분석: {SymbolDisplay(propSymbol)}");
        }
    }

    private static void ProcessFixRoot(FixResult res, string file, SyntaxNode root, SemanticModel semanticModel, CSharpCompilation compilation, bool apply, Encoding enc, string eol, IReadOnlyDictionary<SyntaxTree, SemanticContext>? semanticContexts = null, IReadOnlyDictionary<string, MethodContext>? methodContexts = null)
    {
        var tries = root.DescendantNodes().OfType<TryStatementSyntax>().ToList();
        if (tries.Count == 0) return;

        // 파일별 best-effort 게이팅: 이 파일(트리) 자체의 컴파일 오류만 본다.
        // semanticModel.GetDiagnostics() 는 트리 범위 진단 → 프로젝트 전체 및 CS5001(no-entry) 같은
        // 컴파일-레벨 잡음을 제외하고, 이 파일에서 실제로 발현되는 오류(예: 미해결 타입 CS0246)만 집계한다.
        var baselineErrors = semanticModel.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
        // baseline 이 깨진 파일은 의미 분석 신뢰 불가 → 이 파일만 적용 스킵(아래 파일 단위 게이트).
        bool fileHasBaselineErrors = baselineErrors.Count > 0;
        // REPORTING: completeness=PARTIAL(exit 2) 을 유발하되, 다른 클린 파일 적용을 막지 않는다.
        if (fileHasBaselineErrors)
            res.AddIntegrityFailure($"{file} — baseline compilation errors: {string.Join(", ", baselineErrors.Take(5).Select(d => d.Id))}");

        // FIX 3: 사전 빌드한 newTry 대신 (원본 try → 구체 타입/키) 매핑만 수집하고,
        // 실제 치환은 ReplaceNodes 콜백의 rewritten 인자로 만들어 자식 fix 를 보존한다.
        var typesFor = new Dictionary<TryStatementSyntax, List<string>>();
        var catchFor = new Dictionary<TryStatementSyntax, CatchClauseSyntax>();
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
            if (theCatch.Filter != null)
            {
                res.ManualReview.Add($"{file}:{line} (건너뜀: catch filter 보존 필요)");
                res.Skipped_NonTrivial++;
                continue;
            }

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
            var exMap = AnalyzeTryBlock(tryStmt, semanticModel, compilation: compilation, semanticContexts: semanticContexts, methodContexts: methodContexts);
            var types = GetOrderedResolvedCatchTypes(compilation, exMap);
            if (types.Count == 0)
            {
                // catch-less try 를 절대 만들지 않음 (skip-empty 는 ManualReview 로만 — 커버리지 노트 미발행)
                res.Skipped_Empty++;
                res.ManualReview.Add($"{file}:{line} (건너뜀: 추론된 구체 예외 없음)");
                continue;
            }

            // 권고1b: 실제로 수정될 try(적격 + types>0)에 대해서만 커버리지 노트를 res 에 커밋.
            CollectCoverageWarnings(res, file, line, tryStmt, semanticModel, compilation, semanticContexts, methodContexts);

            var key = (idx++).ToString();
            typesFor[tryStmt] = types;
            catchFor[tryStmt] = theCatch;
            keyFor[tryStmt] = key;
            origFor[key] = (tryStmt.ToString(), line);
            res.ManualReview.Add($"{file}:{line} (주의: 원본 broad catch fallback 보존 — 미추론 예외 escape 방지)");
        }

        if (typesFor.Count == 0) return;

        const string FixAnno = "AUTO-CATCH-FIX";
        var newRoot = root.ReplaceNodes(
            typesFor.Keys,
            (orig, rewritten) => BuildReplacementTry((TryStatementSyntax)rewritten, catchFor[orig], typesFor[orig], eol)
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

        // 파일별 best-effort 게이팅: baseline 이 깨진 파일은 미리보기(PreviewBlocks)는 만들되(가시성) 실제 적용에서 제외.
        // → Modified 미증가·PendingWrite 미추가 이므로, 같은 배치의 다른 클린 파일들은 정상 적용된다.
        if (fileHasBaselineErrors)
        {
            res.SkippedIntegrityFiles++;
            res.ManualReview.Add($"{file} (적용 스킵: baseline 컴파일 오류 — 분석 신뢰불가, 이 파일만 제외)");
            return;
        }

        // 치환된 과도-넓음 catch 수 = 적격 try 수 (중첩 자식은 부모 재구성 시 텍스트로 흡수되어 주석이 소실될 수 있으므로
        // 주석 노드 수가 아닌 typesFor.Count 로 집계한다 — 중첩 케이스에서 실제 치환 건수를 정확히 반영).
        // Modified 는 '실제 적용될 클린 파일'의 catch 만 집계한다(dirty 파일의 예상 수정은 PreviewBlocks+SkippedIntegrityFiles 로만 가시화).
        res.Modified += typesFor.Count;

        if (apply)
        {
            // 권고3: 쓰기는 지연되므로 이 시점 파일은 여전히 원본 → 원본 바이트를 캡처해 적용 직전 대조.
            res.PendingWrites.Add(new PendingWrite(file, formattedText, enc, File.ReadAllBytes(file)));
        }
    }

    private static FixResult RunFixSolution(string solutionPath, bool apply)
    {
        EnsureCodePagesRegistered();
        var res = new FixResult();
        // P1-11: 워크스페이스 로드 실패를 res 에 수집하려면 res 를 워크스페이스 생성 전에 선언해야 한다.
        using var workspace = OpenSolutionWorkspace(solutionPath, out var resolvedSolutionPath, msg => res.WorkspaceFailures.Add(msg));
        var solution = workspace.OpenSolutionAsync(resolvedSolutionPath).GetAwaiter().GetResult();
        var semanticContexts = BuildSemanticContextMap(solution);
        var methodContexts = BuildMethodContextMap(semanticContexts);

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
                    res.AddCoverageWarning($"{full} — linked/multi-context 파일: 최초 프로젝트 컨텍스트만 preview에 사용됨");
                    res.ManualReview.Add($"{full} (중복 프로젝트 컨텍스트 — 최초 1회만 수정)");
                    continue;
                }

                var root = document.GetSyntaxRootAsync().GetAwaiter().GetResult();
                if (root == null)
                {
                    res.SkippedDocuments++;
                    res.ManualReview.Add($"{document.Name} (건너뜀: 구문 트리 없음)");
                    continue;
                }

                // FIX 4: 워크스페이스 root 를 구문 소스로 쓰되, 파일 바이트에서 (인코딩, EOL) 만 감지해 보존 되쓰기.
                var (_, enc, eol) = ReadSourcePreserving(file);
                var semanticModel = compilation.GetSemanticModel(root.SyntaxTree);
                ProcessFixRoot(res, file, root, semanticModel, compilation, apply, enc, eol, semanticContexts, methodContexts);
            }
        }

        // 파일별 best-effort: PendingWrites 에는 클린 파일 쓰기만 담겨 있으므로(dirty 파일은 ProcessFixRoot 에서 제외됨),
        // 솔루션이 PARTIAL(일부 프로젝트 로드 실패/일부 파일 baseline 오류)이어도 클린 파일은 항상 적용한다.
        // 완전성은 IsComplete/exit code 로만 '보고'된다 — 더 이상 apply 를 게이팅하지 않는다.
        if (apply) ApplyPendingWrites(res);

        return res;
    }

    private static FixResult RunFixSourceOnly(string target, bool apply, bool allowPartialApplyForSelfTest = false)
    {
        EnsureCodePagesRegistered();
        var res = new FixResult();
        res.SourceOnlyDiagnostic = true;
        // source-only 는 .sln/MSBuildWorkspace 없이 파일 단위 분석 → 진단 전용(프로덕션은 실제 적용 안 함). 무결성 정책.
        res.AddIntegrityFailure($"{target} — source-only 모드: .sln/MSBuildWorkspace 없이 파일 단위 분석 → 진단 전용(apply 차단)");

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

        if (apply)
        {
            // 프로덕션 source-only 는 절대 적용하지 않는다(진단 전용). selftest 바이패스에서만 클린 파일을 적용.
            if (allowPartialApplyForSelfTest) ApplyPendingWrites(res);
            else res.ManualReview.Add($"{target} (source-only 진단 전용 — 실제 적용 안 함, 적용 차단)");
        }

        return res;
    }

    public static FixResult RunFix(string target, bool apply, bool allowSourceOnlyFallback = false)
    {
        if (_apiDocCache.Count == 0)
        {
            LoadXmlDocumentation();
        }

        // 파일별 best-effort 게이팅(ProcessFixRoot)이 안전을 보장하므로, apply 전 전체 preview 게이트를 제거한다.
        // (이 블록은 apply 경로에서 스캔을 3회로 늘리던 낭비이기도 했다 — 이제 apply 는 1회 스캔으로 직접 진행.)
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
        return RunFixSourceOnly(target, apply);
    }

    public static void WriteFixReport(FixResult res, bool apply)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"===== EXCEPTION FIX REPORT MODE={(apply ? "APPLY" : "PREVIEW")} =====");
        // Modified = '적용 대상(클린 파일)'의 치환 catch 수. baseline 오류 파일은 SkippedIntegrityFiles 로 분리 집계.
        sb.AppendLine($"Modified(적용대상=클린) : {res.Modified}");
        sb.AppendLine($"SkippedIntegrityFiles : {res.SkippedIntegrityFiles}");
        sb.AppendLine($"Skipped_NonTrivial  : {res.Skipped_NonTrivial}");
        sb.AppendLine($"Skipped_Empty       : {res.Skipped_Empty}");
        sb.AppendLine($"Skipped_NotBroad    : {res.Skipped_NotBroad}");
        sb.AppendLine($"CompileReverted     : {res.CompileReverted}");
        sb.AppendLine($"SkippedDocuments    : {res.SkippedDocuments}");
        sb.AppendLine($"IntegrityFailures   : {res.IntegrityFailures.Count}");
        sb.AppendLine($"CoverageWarnings    : {res.CoverageWarnings.Count}");
        sb.AppendLine($"ApplyFailed         : {res.ApplyFailed}");
        if (apply)
            sb.AppendLine($"AppliedFiles       : {res.AppliedFileCount}");
        var completeness = res.IsComplete
            ? (res.HasCoverageGaps ? $"Complete (커버리지 참고 {res.CoverageWarnings.Count}건 — 비차단)" : "Complete")
            : "PARTIAL";
        sb.AppendLine($"Completeness       : {completeness}");
        sb.AppendLine();
        if (res.WorkspaceFailures.Count > 0)
        {
            sb.AppendLine("----- WORKSPACE FAILURES -----");
            foreach (var wf in res.WorkspaceFailures) sb.AppendLine(wf);
            sb.AppendLine();
        }
        if (res.IntegrityFailures.Count > 0)
        {
            sb.AppendLine("----- INTEGRITY FAILURES (차단) -----");
            foreach (var f in res.IntegrityFailures) sb.AppendLine(f);
            sb.AppendLine();
        }
        if (res.CoverageWarnings.Count > 0)
        {
            sb.AppendLine("----- COVERAGE NOTES (비차단 — fallback 보존으로 런타임 안전) -----");
            foreach (var cw in res.CoverageWarnings) sb.AppendLine(cw);
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
}
