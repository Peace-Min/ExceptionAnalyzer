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
                "        catch (Exception ex) { Log(ex); }\n" +
                "    }\n    void Log(Exception e) { }\n}\n");

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
            var res = RunFixSourceOnly(fixtureDir, true, allowPartialApplyForSelfTest: true);

            var broadText = File.ReadAllText(broadPath);
            var emptyText = File.ReadAllText(emptyPath);
            var nonTrivialText = File.ReadAllText(nonTrivialPath);
            var specificText = File.ReadAllText(specificPath);

            bool bareCatch(string t) => System.Text.RegularExpressions.Regex.IsMatch(t, @"catch\s*\{");

            // [1] Broad: 구체 3종 + 기존 단일 호출 본문 보존 + broad fallback 보존
            bool t1 = broadText.Contains("catch (System.ArgumentNullException __autoCatchEx)")
                   && broadText.Contains("catch (System.FormatException __autoCatchEx)")
                   && broadText.Contains("catch (System.OverflowException __autoCatchEx)")
                   && broadText.Contains("Exception ex = __autoCatchEx;")
                   && broadText.Contains("Log(ex)")
                   && !broadText.Contains("System.Diagnostics.Debug.WriteLine(ex)")
                   && broadText.Contains("catch (Exception ex)")
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

            // [6] Empty 변경 → 구체 catch + 빈 catch fallback 보존
            //   FIX 1: 원본이 bare catch{}(변수 없음·빈 본문) → 생성 catch 는 식별자 없이 `catch (System.FormatException)`
            //          (미사용 예외변수 CS0168 방지). 기대 부분문자열을 식별자 없는 형태로 갱신.
            bool t6 = emptyText != before[emptyPath]
                   && emptyText.Contains("[AUTO-CATCH] 원본 빈 catch")
                   && emptyText.Contains("catch (System.FormatException)")
                   && !emptyText.Contains("catch (System.FormatException __autoCatchEx)")
                   && bareCatch(emptyText);

            L("===== SELFTEST-FIX 결과 =====");
            L($"FixResult: Modified={res.Modified}, Skipped_NonTrivial={res.Skipped_NonTrivial}, Skipped_Empty={res.Skipped_Empty}, Skipped_NotBroad={res.Skipped_NotBroad}, CompileReverted={res.CompileReverted}");
            L("--- ManualReview ---");
            foreach (var m in res.ManualReview) L("  " + m);
            L("--- Broad.cs (after) ---");
            L(broadText);
            L("--- Empty.cs (after) ---");
            L(emptyText);
            L("=============================");
            L($"[1] Broad → 구체 3종 + 기존 Log 본문 + broad fallback 보존: {(t1 ? "PASS" : "FAIL")}");
            L($"[2] Broad.cs 컴파일(CS0160 없음): {(t2 ? "PASS" : "FAIL")}");
            L($"[3] NonTrivial 미변경 + ManualReview: {(t3 ? "PASS" : "FAIL")}");
            L($"[4] Specific 미변경 (Skipped_NotBroad): {(t4 ? "PASS" : "FAIL")}");
            L($"[5] Broad 에 using System.Diagnostics; 미추가: {(t5 ? "PASS" : "FAIL")}");
            L($"[6] Empty 변경 → 구체 catch + 빈 catch fallback 보존: {(t6 ? "PASS" : "FAIL")}");

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
            var nestedRes = RunFixSourceOnly(nestedDir, true, allowPartialApplyForSelfTest: true);
            var nestedText = File.ReadAllText(nestedPath);
            int preservedLogCount = System.Text.RegularExpressions.Regex.Matches(nestedText, @"Log\(ex\)").Count;
            bool nestedBroadFallback = nestedText.Contains("catch (Exception ");
            var nestedTree = CSharpSyntaxTree.ParseText(nestedText);
            var nestedComp = CSharpCompilation.Create("NestedCheck").AddReferences(BuildReferences(nestedDir)).AddSyntaxTrees(nestedTree);
            bool nestedNoCs0160 = !nestedComp.GetDiagnostics().Any(d => d.Id == "CS0160");
            bool t7 = nestedBroadFallback && preservedLogCount >= 2 && nestedRes.Modified == 2 && nestedNoCs0160;
            L($"[7] nested-try: {(t7 ? "PASS" : "FAIL")} (Modified={nestedRes.Modified}, preservedLog={preservedLogCount}, broadFallback={nestedBroadFallback}, noCS0160={nestedNoCs0160})");

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
            var sourceSemanticContexts = new Dictionary<SyntaxTree, SemanticContext>
            {
                [treeB] = new SemanticContext(compB, compB.GetSemanticModel(treeB))
            };
            var sourceMethodContexts = BuildMethodContextMap(sourceSemanticContexts);
            var tryStmtA = treeA.GetRoot().DescendantNodes().OfType<TryStatementSyntax>().First();
            bool t8;
            try
            {
                var crossMap = AnalyzeTryBlock(tryStmtA, modelA, compilation: compA, semanticContexts: sourceSemanticContexts, methodContexts: sourceMethodContexts);
                t8 = crossMap.ContainsKey("System.FormatException") || crossMap.ContainsKey("System.OverflowException");
            }
            catch (Exception ex) { t8 = false; L("  [8] 예외 발생: " + ex.GetType().Name + " — " + ex.Message); }
            L($"[8] cross-project propagation: {(t8 ? "PASS" : "FAIL")}");

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

            var encRes = RunFixSourceOnly(encDir, true, allowPartialApplyForSelfTest: true);

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
            var fmtRes = RunFixSourceOnly(fmtDir, true, allowPartialApplyForSelfTest: true);
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
            var exRes = RunFixSourceOnly(exDir, true, allowPartialApplyForSelfTest: true);
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
            var ctorRes = RunFixSourceOnly(ctorDir, true, allowPartialApplyForSelfTest: true);
            var ctorText = File.ReadAllText(ctorPath);
            bool ctorHasIoException =
                   ctorText.Contains("catch (System.UnauthorizedAccessException")
                || ctorText.Contains("catch (System.IO.IOException")
                || ctorText.Contains("catch (System.IO.DirectoryNotFoundException");
            bool t13 = ctorRes.Modified >= 1 && ctorHasIoException && ctorText.Contains("catch (Exception ");
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
            var throwRes = RunFixSourceOnly(throwDir, true, allowPartialApplyForSelfTest: true);
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
            var lambdaRes = RunFixSourceOnly(lambdaDir, true, allowPartialApplyForSelfTest: true);
            var lambdaText = File.ReadAllText(lambdaPath);
            bool lambdaUnchanged = lambdaText == lambdaBefore;
            bool t15 = !lambdaText.Contains("FormatException") && lambdaUnchanged;
            L($"[15] 람다 경계: {(t15 ? "PASS" : "FAIL")} (unchanged={lambdaUnchanged}, Skipped_Empty={lambdaRes.Skipped_Empty})");

            // ── [16] 중첩 try 보호블록 경계 : 내부 catch가 일부 예외만 잡을 수 있으므로 외부 broad catch는 보존 ──
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
            var nestGuardRes = RunFixSourceOnly(nestGuardDir, true, allowPartialApplyForSelfTest: true);
            var nestGuardText = File.ReadAllText(nestGuardPath);
            int outerBroadCount = System.Text.RegularExpressions.Regex.Matches(nestGuardText, @"catch \(Exception ex\)").Count;
            bool t16 = outerBroadCount == 1 && nestGuardText.Contains("OverflowException") && nestGuardText != nestGuardBefore;
            L($"[16] 중첩 try 미처리 예외 전파: {(t16 ? "PASS" : "FAIL")} (broadCount={outerBroadCount}, hasOverflow={nestGuardText.Contains("OverflowException")}, changed={nestGuardText != nestGuardBefore})");

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

            // ── [18] catch filter 보존 : catch(Exception) when (...) 은 자동수정하지 않고 수동검토로 넘김 ──
            var filterDir = Path.Combine(fixtureDir, "filter");
            Directory.CreateDirectory(filterDir);
            var filterPath = Path.Combine(filterDir, "Filter.cs");
            File.WriteAllText(filterPath,
                "using System;\n" +
                "class Cf {\n" +
                "    void M(string s) {\n" +
                "        try { int n = int.Parse(s); } catch (Exception ex) when (ex.Message.Length > 0) { Log(ex); }\n" +
                "    }\n" +
                "    void Log(Exception e) { }\n" +
                "}\n");
            var filterBefore = File.ReadAllText(filterPath);
            var filterRes = RunFixSourceOnly(filterDir, true, allowPartialApplyForSelfTest: true);
            var filterText = File.ReadAllText(filterPath);
            bool t18 = filterText == filterBefore
                    && filterRes.Modified == 0
                    && filterRes.Skipped_NonTrivial >= 1
                    && filterRes.ManualReview.Any(m => m.Contains("catch filter"));
            L($"[18] catch filter 보존/스킵: {(t18 ? "PASS" : "FAIL")} (Modified={filterRes.Modified}, NonTrivial={filterRes.Skipped_NonTrivial})");

            // ── [19] integrity completeness : source-only 모드는 무결성 실패(IntegrityFailure)로 PARTIAL 보고 ──
            bool t19 = !res.IsComplete
                    && res.IntegrityFailures.Count > 0;
            L($"[19] integrity completeness (source-only PARTIAL): {(t19 ? "PASS" : "FAIL")} (partial={!res.IsComplete}, integrity={res.IntegrityFailures.Count}, coverage={res.CoverageWarnings.Count})");

            // ── [20] public API apply gate : PARTIAL(source-only) 은 직접 RunFix apply 도 쓰기 금지 ──
            var publicGateDir = Path.Combine(fixtureDir, "publicgate");
            Directory.CreateDirectory(publicGateDir);
            var publicGatePath = Path.Combine(publicGateDir, "Gate.cs");
            File.WriteAllText(publicGatePath,
                "using System;\nclass Pg { void M(string s) { try { int n = int.Parse(s); } catch (Exception ex) { Log(ex); } } void Log(Exception e) { } }\n");
            var publicGateBefore = File.ReadAllText(publicGatePath);
            var publicGateRes = RunFix(publicGateDir, true, allowSourceOnlyFallback: true);
            var publicGateAfter = File.ReadAllText(publicGatePath);
            bool t20 = publicGateAfter == publicGateBefore
                    && publicGateRes.Modified > 0
                    && !publicGateRes.IsComplete
                    && publicGateRes.ManualReview.Any(m => m.Contains("적용 차단"));
            L($"[20] public API PARTIAL apply gate: {(t20 ? "PASS" : "FAIL")} (unchanged={publicGateAfter == publicGateBefore}, ModifiedPreview={publicGateRes.Modified}, Complete={publicGateRes.IsComplete})");

            // ── [21] coverage gap 은 비차단 : foreach/using 커버리지 노트가 있어도 fix 는 정상 적용됨 ──
            //     (권고1) 원본 broad catch 를 fallback 으로 보존하므로 커버리지 갭은 런타임 안전 → apply 를 막지 않는다.
            var covDir = Path.Combine(fixtureDir, "coveragegap");
            Directory.CreateDirectory(covDir);
            var covPath = Path.Combine(covDir, "CoverageGap.cs");
            File.WriteAllText(covPath,
                "using System;\nusing System.Collections.Generic;\n" +
                "class Cg {\n" +
                "  void M(string s, IEnumerable<int> xs, IDisposable d) {\n" +
                "    try { int n = int.Parse(s); foreach (var x in xs) { } using (d) { } }\n" +
                "    catch (Exception ex) { Log(ex); }\n" +
                "  }\n" +
                "  void Log(Exception e) { }\n" +
                "}\n");
            var covBefore = File.ReadAllText(covPath);
            var covRes = RunFixSourceOnly(covDir, true, allowPartialApplyForSelfTest: true);
            var covAfter = File.ReadAllText(covPath);
            bool covNote = covRes.CoverageWarnings.Any(w => w.Contains("foreach") || w.Contains("using"));
            bool covModified = covAfter != covBefore
                            && covAfter.Contains("catch (System.FormatException __autoCatchEx)")
                            && covAfter.Contains("catch (Exception ex)"); // broad fallback 보존
            bool t21 = covNote && covModified && covRes.Modified >= 1;
            L("--- CoverageGap.cs (after) ---");
            L(covAfter);
            L($"[21] coverage gap 비차단(fix 적용됨): {(t21 ? "PASS" : "FAIL")} (covNote={covNote}, modified={covModified}, Modified={covRes.Modified})");

            // ── [22] classification unit : 커버리지 경고는 IsComplete 를 막지 않고, 무결성 실패는 막는다 ──
            var r22 = new FixResult();
            r22.AddCoverageWarning("x");
            bool t22a = r22.IsComplete; // coverage 만으로는 Complete 유지
            r22.AddIntegrityFailure("y");
            bool t22b = !r22.IsComplete; // integrity 추가 시 PARTIAL
            bool t22 = t22a && t22b;
            L($"[22] classification (coverage 비차단 / integrity 차단): {(t22 ? "PASS" : "FAIL")} (coverageComplete={t22a}, integrityBlocks={t22b})");

            // ── [23] TOCTOU 가드 : scan 이후 파일이 바뀌면(ExpectedOriginalBytes 불일치) 쓰기 전체 중단 ──
            var toctouDir = Path.Combine(fixtureDir, "toctou");
            Directory.CreateDirectory(toctouDir);
            var toctouPath = Path.Combine(toctouDir, "Toctou.cs");
            var toctouOriginal = "original content";
            File.WriteAllText(toctouPath, toctouOriginal);
            var r23 = new FixResult();
            r23.PendingWrites.Add(new PendingWrite(toctouPath, "new content", Encoding.UTF8, Encoding.UTF8.GetBytes("DIFFERENT")));
            ApplyPendingWrites(r23);
            var toctouAfter = File.ReadAllText(toctouPath);
            bool t23 = r23.ApplyFailed && toctouAfter == toctouOriginal;
            L($"[23] TOCTOU 가드(외부 수정 감지→쓰기 중단): {(t23 ? "PASS" : "FAIL")} (applyFailed={r23.ApplyFailed}, unchanged={toctouAfter == toctouOriginal})");

            // ── [24] 해시 일치 시 정상 적용 : ExpectedOriginalBytes == 현재 바이트면 쓰기 성공 ──
            var okDir = Path.Combine(fixtureDir, "hashok");
            Directory.CreateDirectory(okDir);
            var okPath = Path.Combine(okDir, "HashOk.cs");
            var okOriginal = "original body";
            File.WriteAllText(okPath, okOriginal, new UTF8Encoding(false));
            var okBytes = File.ReadAllBytes(okPath);
            var r24 = new FixResult();
            r24.PendingWrites.Add(new PendingWrite(okPath, "updated body", new UTF8Encoding(false), okBytes));
            ApplyPendingWrites(r24);
            var okAfter = File.ReadAllText(okPath);
            bool t24 = !r24.ApplyFailed && okAfter == "updated body" && r24.AppliedFileCount == 1;
            L($"[24] 해시 일치 시 정상 적용: {(t24 ? "PASS" : "FAIL")} (applyFailed={r24.ApplyFailed}, updated={okAfter == "updated body"}, appliedCount={r24.AppliedFileCount})");

            // ── [25] 파일별 best-effort 게이팅 : 클린 파일은 적용, baseline 오류 파일은 스킵(다른 클린 파일 적용을 막지 않음) ──
            var gatingDir = Path.Combine(fixtureDir, "gating");
            Directory.CreateDirectory(gatingDir);
            var cleanPath = Path.Combine(gatingDir, "Clean.cs");
            var dirtyPath = Path.Combine(gatingDir, "Dirty.cs");
            // 클린: 적격 broad catch(int.Parse) — baseline 컴파일 클린
            File.WriteAllText(cleanPath,
                "using System;\n" +
                "class Clean { void M(string s) { try { int n = int.Parse(s); } catch (Exception ex) { Log(ex); } } void Log(Exception e) { } }\n");
            // dirty: 동일한 적격 broad catch 이지만, 미해결 타입 필드(CS0246)로 baseline 컴파일 오류를 가짐
            File.WriteAllText(dirtyPath,
                "using System;\n" +
                "class Dirty {\n" +
                "    private Undefined _x;\n" +
                "    void M(string s) { try { int n = int.Parse(s); } catch (Exception ex) { Log(ex); } }\n" +
                "    void Log(Exception e) { }\n" +
                "}\n");
            var cleanBeforeBytes = File.ReadAllBytes(cleanPath);
            var dirtyBeforeBytes = File.ReadAllBytes(dirtyPath);
            var gatingRes = RunFixSourceOnly(gatingDir, true, allowPartialApplyForSelfTest: true);
            var cleanAfterBytes = File.ReadAllBytes(cleanPath);
            var dirtyAfterBytes = File.ReadAllBytes(dirtyPath);
            var cleanAfterText = File.ReadAllText(cleanPath);
            bool cleanApplied = !cleanBeforeBytes.SequenceEqual(cleanAfterBytes)
                             && cleanAfterText.Contains("catch (System.FormatException __autoCatchEx)")
                             && cleanAfterText.Contains("catch (Exception ex)"); // broad fallback 보존
            bool dirtyUnchanged = dirtyBeforeBytes.SequenceEqual(dirtyAfterBytes);
            bool t25 = cleanApplied && dirtyUnchanged && gatingRes.SkippedIntegrityFiles >= 1 && gatingRes.Modified >= 1;
            L("--- gating/Clean.cs (after) ---");
            L(cleanAfterText);
            L($"[25] 파일별 best-effort 게이팅: {(t25 ? "PASS" : "FAIL")} (cleanApplied={cleanApplied}, dirtyUnchanged={dirtyUnchanged}, SkippedIntegrity={gatingRes.SkippedIntegrityFiles}, Modified={gatingRes.Modified})");

            // ── [26] FIX 1: 생성 catch 가 미사용 예외변수 경고(CS0168/CS0219)를 유발하지 않음 ──
            //   (a) catch (Exception) { }        (변수 없음·빈 본문)  → catch (System.X)            식별자 없음
            //   (b) catch (Exception) { DoLog(); }(변수 없음·비참조 본문) → catch (System.X) { DoLog(); } 식별자 없음
            //   (c) catch (Exception ex) { Log(ex); }(변수·참조 본문)  → catch (System.X __autoCatchEx) { Exception ex = __autoCatchEx; Log(ex); } 별칭 유지
            var unusedDir = Path.Combine(fixtureDir, "unusedvar");
            Directory.CreateDirectory(unusedDir);
            var unusedPath = Path.Combine(unusedDir, "Unused.cs");
            File.WriteAllText(unusedPath,
                "using System;\n" +
                "class Unused {\n" +
                "    void A(string s) { try { int.Parse(s); } catch (Exception) { } }\n" +
                "    void B(string s) { try { int.Parse(s); } catch (Exception) { DoLog(); } }\n" +
                "    void C(string s) { try { int.Parse(s); } catch (Exception ex) { Log(ex); } }\n" +
                "    void DoLog() { }\n" +
                "    void Log(Exception e) { }\n" +
                "}\n");
            var unusedRes = RunFixSourceOnly(unusedDir, true, allowPartialApplyForSelfTest: true);
            var unusedText = File.ReadAllText(unusedPath);
            var unusedTree = CSharpSyntaxTree.ParseText(unusedText);
            var unusedComp = CSharpCompilation.Create("UnusedCheck")
                .AddReferences(BuildReferences(unusedDir))
                .AddSyntaxTrees(unusedTree);
            var unusedDiags = unusedComp.GetDiagnostics();
            bool noUnusedWarn = !unusedDiags.Any(d => d.Id == "CS0168" || d.Id == "CS0219");
            var uMethods = unusedTree.GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>()
                .ToDictionary(m => m.Identifier.ValueText);
            // 생성 catch = 완전수식(System.*) 타입의 catch (fallback 은 원본 그대로 'Exception' 이라 제외됨)
            List<CatchClauseSyntax> GenCatches(string methodName) =>
                uMethods[methodName].DescendantNodes().OfType<CatchClauseSyntax>()
                    .Where(c => c.Declaration != null && c.Declaration.Type.ToString().StartsWith("System.", StringComparison.Ordinal))
                    .ToList();
            bool GenNoId(string methodName)
            {
                var g = GenCatches(methodName);
                return g.Count > 0 && g.All(c => string.IsNullOrEmpty(c.Declaration!.Identifier.ValueText));
            }
            bool GenAlias(string methodName)
            {
                var g = GenCatches(methodName);
                return g.Count > 0
                    && g.All(c => c.Declaration!.Identifier.ValueText == "__autoCatchEx")
                    && uMethods[methodName].ToString().Contains("Exception ex = __autoCatchEx;");
            }
            bool aShape = GenNoId("A");
            bool bShape = GenNoId("B");
            bool cShape = GenAlias("C");
            bool t26 = unusedRes.Modified >= 3 && noUnusedWarn && aShape && bShape && cShape;
            L("--- Unused.cs (after) ---");
            L(unusedText);
            L($"[26] 미사용 예외변수 경고 없음(생성 catch): {(t26 ? "PASS" : "FAIL")} (noUnusedWarn={noUnusedWarn}, a(noId)={aShape}, b(noId)={bShape}, c(alias)={cShape}, Modified={unusedRes.Modified})");

            // ── [27] solution-mode per-file 게이팅 통합 ([25]는 source-only 전용이었던 갭 보강) ──
            //   MSBuildWorkspace/restore 헤드리스 로드는 selftest 환경에서 불안정 → 스펙의 FALLBACK 경로 사용:
            //   두 문서(Clean/Dirty)를 담은 in-memory 공유 컴파일에 대해 RunFixSolution 과 동일하게
            //   ProcessFixRoot 를 파일별로 구동하고 ApplyPendingWrites 로 마감. 파일 단위 진단은 트리 스코프라
            //   Dirty(baseline CS0246)만 스킵되고 Clean 은 적용되는 per-file 게이팅을 그대로 재현한다.
            var slnGateDir = Path.Combine(fixtureDir, "slngate");
            Directory.CreateDirectory(slnGateDir);
            var slnCleanPath = Path.Combine(slnGateDir, "Clean.cs");
            var slnDirtyPath = Path.Combine(slnGateDir, "Dirty.cs");
            File.WriteAllText(slnCleanPath,
                "using System;\n" +
                "class CleanP { void M(string s) { try { int n = int.Parse(s); } catch (Exception ex) { Log(ex); } } void Log(Exception e) { } }\n");
            File.WriteAllText(slnDirtyPath,
                "using System;\n" +
                "class DirtyP {\n" +
                "    private Undefined _x;\n" +
                "    void M(string s) { try { int n = int.Parse(s); } catch (Exception ex) { Log(ex); } }\n" +
                "    void Log(Exception e) { }\n" +
                "}\n");
            var slnDirtyBeforeBytes = File.ReadAllBytes(slnDirtyPath);
            var slnRes = new FixResult(); // NOT source-only (SourceOnlyDiagnostic=false) → 무결성 전역차단 없음, 솔루션 경로와 동일
            var (slnCleanCode, slnCleanEnc, slnCleanEol) = ReadSourcePreserving(slnCleanPath);
            var (slnDirtyCode, slnDirtyEnc, slnDirtyEol) = ReadSourcePreserving(slnDirtyPath);
            var slnCleanTree = CSharpSyntaxTree.ParseText(slnCleanCode, path: slnCleanPath, encoding: slnCleanEnc);
            var slnDirtyTree = CSharpSyntaxTree.ParseText(slnDirtyCode, path: slnDirtyPath, encoding: slnDirtyEnc);
            var slnComp = CSharpCompilation.Create("SlnGate")
                .AddReferences(BuildReferences(slnGateDir))
                .AddSyntaxTrees(slnCleanTree, slnDirtyTree);
            ProcessFixRoot(slnRes, slnCleanPath, slnCleanTree.GetRoot(), slnComp.GetSemanticModel(slnCleanTree), slnComp, true, slnCleanEnc, slnCleanEol);
            ProcessFixRoot(slnRes, slnDirtyPath, slnDirtyTree.GetRoot(), slnComp.GetSemanticModel(slnDirtyTree), slnComp, true, slnDirtyEnc, slnDirtyEol);
            ApplyPendingWrites(slnRes);
            var slnCleanAfter = File.ReadAllText(slnCleanPath);
            var slnDirtyAfterBytes = File.ReadAllBytes(slnDirtyPath);
            bool slnCleanApplied = slnCleanAfter.Contains("catch (System.FormatException __autoCatchEx)")
                                && slnCleanAfter.Contains("catch (Exception ex)"); // broad fallback 보존
            bool slnDirtyUnchanged = slnDirtyBeforeBytes.SequenceEqual(slnDirtyAfterBytes);
            bool slnPartial = !slnRes.IsComplete; // SkippedIntegrityFiles>=1 → PARTIAL(exit 2 상당)
            bool t27 = slnCleanApplied && slnDirtyUnchanged
                    && slnRes.SkippedIntegrityFiles >= 1 && slnRes.AppliedFileCount >= 1 && slnPartial;
            L("[27] path=LIGHTER(in-memory ProcessFixRoot per-file; MSBuild/restore 회피)");
            L("--- slngate/Clean.cs (after) ---");
            L(slnCleanAfter);
            L($"[27] solution-mode per-file 게이팅: {(t27 ? "PASS" : "FAIL")} (cleanApplied={slnCleanApplied}, dirtyUnchanged={slnDirtyUnchanged}, SkippedIntegrity={slnRes.SkippedIntegrityFiles}, Applied={slnRes.AppliedFileCount}, PARTIAL={slnPartial})");

            allPass = previewUnchanged && t1 && t2 && t3 && t4 && t5 && t6
                   && t7 && t8 && t9 && t10 && t11 && t12
                   && t13 && t14 && t15 && t16 && t17 && t18 && t19 && t20 && t21
                   && t22 && t23 && t24 && t25 && t26 && t27;
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
