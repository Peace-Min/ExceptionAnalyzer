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
