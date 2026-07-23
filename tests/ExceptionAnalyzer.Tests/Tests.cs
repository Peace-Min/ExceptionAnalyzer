using System;
using System.IO;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Xunit;

namespace ExceptionAnalyzer.Tests
{
    // Program 은 global 네임스페이스의 internal 클래스 → global::Program 로 참조하며,
    // 앱 csproj 의 <InternalsVisibleTo Include="ExceptionAnalyzer.Tests"/> 로 접근 허용됨.
    public class Tests
    {
        // 코어 셀프테스트 게이트(정렬·Exception 제거·셀프컴파일 검증)가 통과해야 한다.
        [Fact]
        public void SelfTest_Core_Passes()
        {
            Assert.Equal(0, global::Program.RunSelfTestHeadless("--selftest"));
        }

        // XML 문서 조회 경로 게이트. v4.7.2 ko 참조 어셈블리가 없는 머신에서는 CI 관용적으로 스킵.
        [Fact]
        public void SelfTest_Xml_Passes()
        {
            if (!Directory.Exists(@"C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.7.2"))
                return; // 참조 어셈블리 부재 → 스킵(관용)
            Assert.Equal(0, global::Program.RunSelfTestHeadless("--selftest-xml"));
        }

        // FIX 엔진 종단 게이트(preview/apply·인코딩·중첩·경계 등 21개 항목).
        [Fact]
        public void SelfTest_Fix_Passes()
        {
            Assert.Equal(0, global::Program.RunSelfTestFix());
        }

        // FIX 1: 생성 catch 는 미사용 예외변수 경고(CS0168/CS0219)를 유발하지 않아야 한다.
        //  - 원본에 변수 없음/빈 본문 → catch (System.X) 식별자 없음
        //  - 원본에 변수·참조 본문   → catch (System.X __autoCatchEx) { Exception ex = __autoCatchEx; ... } 별칭 유지
        // 대상 프로젝트가 TreatWarningsAsErrors 라도 self-revert 되지 않도록 보장한다.
        [Fact]
        public void GeneratedCatch_NoUnusedVariableWarning()
        {
            // net472 참조 어셈블리 부재 시 int.Parse 미해석 → 구체 예외 없음. selftest와 동일 전제로 스킵(관용).
            if (!Directory.Exists(@"C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.7.2"))
                return;

            var dir = Path.Combine(Path.GetTempPath(), "ea_xunit_unusedvar_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var file = Path.Combine(dir, "Unused.cs");
                File.WriteAllText(file,
                    "using System;\n" +
                    "class Unused {\n" +
                    "    void A(string s) { try { int.Parse(s); } catch (Exception) { } }\n" +
                    "    void B(string s) { try { int.Parse(s); } catch (Exception) { DoLog(); } }\n" +
                    "    void C(string s) { try { int.Parse(s); } catch (Exception ex) { Log(ex); } }\n" +
                    "    void DoLog() { }\n" +
                    "    void Log(Exception e) { }\n" +
                    "}\n");

                // selftest와 동일한 apply 시임(RunFixSourceOnly internal + allowPartialApplyForSelfTest).
                var res = global::Program.RunFixSourceOnly(dir, apply: true, allowPartialApplyForSelfTest: true);
                var applied = File.ReadAllText(file);

                var tree = CSharpSyntaxTree.ParseText(applied);
                var comp = CSharpCompilation.Create("UnusedCheck")
                    .AddReferences(global::Program.BuildReferences(dir))
                    .AddSyntaxTrees(tree);
                var diags = comp.GetDiagnostics();

                Assert.True(res.Modified >= 3);
                Assert.DoesNotContain(diags, d => d.Id == "CS0168" || d.Id == "CS0219");

                var methods = tree.GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>()
                    .ToDictionary(m => m.Identifier.ValueText);
                List<CatchClauseSyntax> GenCatches(string name) =>
                    methods[name].DescendantNodes().OfType<CatchClauseSyntax>()
                        .Where(c => c.Declaration != null && c.Declaration.Type.ToString().StartsWith("System.", StringComparison.Ordinal))
                        .ToList();

                // (a)/(b): 생성 catch 는 식별자 없음
                foreach (var m in new[] { "A", "B" })
                {
                    var g = GenCatches(m);
                    Assert.NotEmpty(g);
                    Assert.All(g, c => Assert.True(string.IsNullOrEmpty(c.Declaration!.Identifier.ValueText)));
                }
                // (c): 별칭 형태 유지
                var cGen = GenCatches("C");
                Assert.NotEmpty(cGen);
                Assert.All(cGen, c => Assert.Equal("__autoCatchEx", c.Declaration!.Identifier.ValueText));
                Assert.Contains("Exception ex = __autoCatchEx;", methods["C"].ToString());
            }
            finally
            {
                if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
            }
        }

        // P1-9 진단 지문: 같은 ID(CS0029)의 오류가 1→2 로 늘면 '신규 오류'로 검출,
        // 동일 입력이면 빈 목록이어야 한다.
        [Fact]
        public void DiffIntroducedErrors_DetectsSameIdNewError()
        {
            var refs = RuntimeRefs();

            CSharpCompilation Comp(string name, string src) =>
                CSharpCompilation.Create(name)
                    .WithOptions(new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary))
                    .AddReferences(refs)
                    .AddSyntaxTrees(CSharpSyntaxTree.ParseText(src));

            var oneError = Comp("one", "class C { void M() { int x = \"a\"; } }");
            var twoErrors = Comp("two", "class C { void M() { int x = \"a\"; int y = \"b\"; } }");

            var introduced = global::Program.DiffIntroducedErrors(
                oneError.GetDiagnostics(), twoErrors.GetDiagnostics());
            Assert.NotEmpty(introduced);

            var same = global::Program.DiffIntroducedErrors(
                oneError.GetDiagnostics(), oneError.GetDiagnostics());
            Assert.Empty(same);
        }

        [Fact]
        public void RunFix_SourceOnlyApplyBlocked_DoesNotWrite()
        {
            var dir = Path.Combine(Path.GetTempPath(), "ea_xunit_sourceonly_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var file = Path.Combine(dir, "Gate.cs");
                var source = "using System; class C { void M(string s) { try { int.Parse(s); } catch (Exception ex) { Log(ex); } } void Log(Exception e) { } }";
                File.WriteAllText(file, source);

                var result = global::Program.RunFix(dir, apply: true, allowSourceOnlyFallback: true);

                Assert.False(result.IsComplete);
                // 권고1: source-only 정책은 커버리지 경고가 아니라 무결성 실패(차단)로 이동.
                Assert.Contains(result.IntegrityFailures, m => m.Contains("source-only"));
                Assert.Contains(result.ManualReview, m => m.Contains("적용 차단"));
                Assert.Equal(source, File.ReadAllText(file));
            }
            finally
            {
                if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
            }
        }

        [Fact]
        public void AnalyzeTryBlock_NestedTryPropagatesOnlyUnhandledExceptions()
        {
            var source = @"
using System;
class C {
    void M() {
        try {
            try {
                if (DateTime.Now.Ticks > 0) throw new FormatException();
                throw new OverflowException();
            }
            catch (FormatException) { }
        }
        catch { }
    }
}";
            var tree = CSharpSyntaxTree.ParseText(source);
            var compilation = CSharpCompilation.Create("nested")
                .WithOptions(new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary))
                .AddReferences(RuntimeRefs())
                .AddSyntaxTrees(tree);
            var model = compilation.GetSemanticModel(tree);
            var root = tree.GetRoot();
            var outerTry = root.DescendantNodes().OfType<TryStatementSyntax>().First();

            var result = global::Program.AnalyzeTryBlock(outerTry, model, compilation: compilation);

            Assert.Contains("System.OverflowException", result.Keys);
            Assert.DoesNotContain("System.FormatException", result.Keys);
        }

        // 권고1: 미지원 실행 지점(foreach 등)은 이제 비차단 커버리지 노트로만 기록된다.
        // apply 차단은 커버리지가 아니라 source-only 무결성 정책이 담당한다(파일 불변 확인).
        [Fact]
        public void RunFix_UnsupportedExecutionEmitsCoverageNote_SourceOnlyBlocksApply()
        {
            var dir = Path.Combine(Path.GetTempPath(), "ea_xunit_unsupported_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var file = Path.Combine(dir, "Unsupported.cs");
                // int.Parse 로 구체 예외를 확보(types>0) → try 가 수정 대상이 되어 foreach 커버리지 노트가 기록됨.
                var source =
                    "using System; using System.Collections.Generic; " +
                    "struct Risky { public static Risky operator +(Risky a, Risky b) => throw new InvalidOperationException(); } " +
                    "class C { void M(string s, IEnumerable<int> xs) { try { int n = int.Parse(s); var r = new Risky() + new Risky(); foreach (var x in xs) { } } catch (Exception ex) { Log(ex); } } void Log(Exception e) { } }";
                File.WriteAllText(file, source);

                var result = global::Program.RunFix(dir, apply: true, allowSourceOnlyFallback: true);

                Assert.False(result.IsComplete); // source-only 무결성 실패
                Assert.Contains(result.CoverageWarnings, m => m.Contains("미지원 실행 지점"));
                Assert.Equal(source, File.ReadAllText(file)); // apply 차단 → 파일 불변
            }
            finally
            {
                if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
            }
        }

        // 권고1: 커버리지 경고만으로는 IsComplete 를 막지 못하고, 무결성 실패는 막는다.
        [Fact]
        public void IsComplete_CoverageWarningIsNonBlocking()
        {
            var r = new global::Program.FixResult();
            r.AddCoverageWarning("x");
            Assert.True(r.IsComplete);
            r.AddIntegrityFailure("y");
            Assert.False(r.IsComplete);
        }

        // 파일별 best-effort 게이팅: baseline 오류로 적용 스킵된 파일(SkippedIntegrityFiles)이 있으면
        // 완전성 보고는 PARTIAL(IsComplete=false, exit 2)이어야 한다. (클린 파일 적용 자체는 막지 않음 — 종단 검증은 selftest [25].)
        [Fact]
        public void IsComplete_False_WhenSkippedIntegrityFiles()
        {
            var r = new global::Program.FixResult();
            Assert.True(r.IsComplete); // 아무 문제 없으면 Complete
            r.SkippedIntegrityFiles = 1;
            Assert.False(r.IsComplete); // 파일별 무결성 스킵이 있으면 PARTIAL
        }

        // 권고3: scan 이후 외부 수정 감지 시(ExpectedOriginalBytes 불일치) 배치 전체 쓰기를 중단하고 실패로 보고.
        [Fact]
        public void ApplyPendingWrites_DetectsExternalModification()
        {
            var dir = Path.Combine(Path.GetTempPath(), "ea_xunit_toctou_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var file = Path.Combine(dir, "T.cs");
                var original = "original content";
                File.WriteAllText(file, original);

                var r = new global::Program.FixResult();
                r.PendingWrites.Add(new global::Program.PendingWrite(
                    file, "new content", System.Text.Encoding.UTF8, System.Text.Encoding.UTF8.GetBytes("DIFFERENT")));

                global::Program.ApplyPendingWrites(r);

                Assert.True(r.ApplyFailed);
                Assert.Equal(original, File.ReadAllText(file));
            }
            finally
            {
                if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
            }
        }

        // 현재 런타임의 전체 참조 어셈블리(BCL 포함)를 메타데이터 참조로 구성 — int/string 바인딩 보장.
        private static MetadataReference[] RuntimeRefs()
        {
            var tpa = (AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES") as string) ?? string.Empty;
            return tpa.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
                      .Where(p => p.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && File.Exists(p))
                      .Select(p => (MetadataReference)MetadataReference.CreateFromFile(p))
                      .ToArray();
        }
    }
}
