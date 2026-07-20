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
}
