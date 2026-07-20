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
}
