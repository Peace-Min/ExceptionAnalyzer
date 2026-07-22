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
                Assert.Contains(result.CoverageWarnings, m => m.Contains("source-only"));
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

        [Fact]
        public void RunFix_UnsupportedExecutionCoverageBlocksApply()
        {
            var dir = Path.Combine(Path.GetTempPath(), "ea_xunit_unsupported_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var file = Path.Combine(dir, "Unsupported.cs");
                var source =
                    "using System; using System.Collections.Generic; " +
                    "struct Risky { public static Risky operator +(Risky a, Risky b) => throw new InvalidOperationException(); } " +
                    "class C { void M(IEnumerable<int> xs) { try { var r = new Risky() + new Risky(); foreach (var x in xs) { } } catch (Exception ex) { Log(ex); } } void Log(Exception e) { } }";
                File.WriteAllText(file, source);

                var result = global::Program.RunFix(dir, apply: true, allowSourceOnlyFallback: true);

                Assert.False(result.IsComplete);
                Assert.Contains(result.CoverageWarnings, m => m.Contains("미지원 실행 지점"));
                Assert.Equal(source, File.ReadAllText(file));
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
