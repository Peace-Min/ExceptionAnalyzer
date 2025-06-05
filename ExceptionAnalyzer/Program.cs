using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis;
using System.Xml.Linq;
using System;
using System.Linq;
using Microsoft.CodeQuality.Analyzers.ApiDesignGuidelines;
using System.Reflection;


public class ApiDocumentation
{
    public string MethodName { get; set; }
    public string Summary { get; set; }
    public Dictionary<string, string> Exceptions { get; set; } = new Dictionary<string, string>();
}


internal class Program
{
    private static List<string> methodExceptionList = new List<string>();
    private static readonly string NET_FRAMEWORK_PATH = @"C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.7.2\ko";
    private static Dictionary<string, ApiDocumentation> _apiDocCache = new Dictionary<string, ApiDocumentation>();

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
                Console.WriteLine($"XML 문서 로드 중 오류 발생: {xmlFile}");
                Console.WriteLine(ex.Message);
            }
        }
    }

    private static async Task Main(string[] args)
    {
        // XML 문서 로드
        Console.WriteLine("📚 .NET Framework XML 문서 로딩 중...");
        LoadXmlDocumentation();
        Console.WriteLine($"✅ {_apiDocCache.Count}개의 API 문서 로드 완료");

        // 1. 분석할 디렉토리 지정 
        // ※ 분석 대상 프로젝트 경로 설정※
        var targetDirectory = @"C:\\Users\\CEO\\Desktop\\ㅄㅊ\\StatusDisplayEquipment\\StatusDisplayEquipment\\StatusDisplayEquipment";//string.Empty; 
        var lastFolderName = new DirectoryInfo(targetDirectory).Name;

        // 2. 출력 파일 경로 지정
        var outputPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"{lastFolderName}_ApiCallCandidates.txt");
        var unregisteredExceptionMapPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"{lastFolderName}_UnregisteredExceptionMap.txt"); // ExceptionMap에 등록안된 메소드만 별도로 저장

        // 3. 출력 스트림 오픈
        using var writer = new StreamWriter(outputPath);
        using var exceptionWriter = new StreamWriter(unregisteredExceptionMapPath);

        Console.WriteLine($"🔍 디렉토리 분석 시작: {targetDirectory}");

        // 4. 디렉토리 내 모든 .cs 파일 재귀적으로 수집
        var csFiles = Directory.GetFiles(targetDirectory, "*.cs", SearchOption.AllDirectories);

        // 5. 각 파일에 대해 반복 수행
        foreach (var file in csFiles)
        {
            // 5-1. 파일 내용을 문자열로 읽어옴 
            var code = await File.ReadAllTextAsync(file);

            // 5-2. Roslyn으로 C# 구문 트리(SyntaxTree) 생성
            var tree = CSharpSyntaxTree.ParseText(code);

            // 5-3. 구문 트리에서 루트 노드 추출 (SyntaxNode)
            var root = await tree.GetRootAsync();

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
                Console.WriteLine(message);
                writer.WriteLine(message);


                // 9-3. 각 호출에 대해 의미 정보 추출
                methodExceptionList = new List<string>();
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
                        // _apiDocCache에서 메서드 이름을 포함한 모든 키를 찾음
                        var matchedDocs = _apiDocCache
                                                     .Where(kvp =>
                                                     {
                                                         var fullMethodSignature = kvp.Key;
                                                         var nameOnly = fullMethodSignature.Split('.').Last().Split('(')[0]; // 예: IndexOf
                                                         return nameOnly == methodName;
                                                     })
                                                     .Select(kvp => kvp.Value)
                                                     .ToList();

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
                                    if (!methodExceptionList.Contains(exception.Key))
                                    {
                                        methodExceptionList.Add(exception.Key);
                                    }

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
                            Console.WriteLine($"        → 예상 예외: {exception.Key}");
                        }
                    }
                    else
                    {
                        var nonFrameworkCall = $"프레임워크에 등록되지 않은 API : {methodSymbol.ContainingNamespace}.{methodSymbol.ContainingType.Name}.{methodSymbol.Name}";
                        writer.WriteLine($"    🔧 {nonFrameworkCall}()");
                        Console.WriteLine($"    🔧 {nonFrameworkCall}()");

                        // 해당 메서드 정의 위치를 찾음 (재귀 분석용)
                        var methodDeclSyntax = methodSymbol.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() as MethodDeclarationSyntax;

                        if (methodDeclSyntax != null)
                        {
                            AnalyzeInternalMethod(methodDeclSyntax, semanticModel, writer, exceptionWriter, methodFullName, 1);
                        }
                    }

                }

                writer.WriteLine($"🐙 최종 Exception");
                Console.WriteLine($"🐙 최종 Exception");
                foreach (var exception in methodExceptionList)
                {
                    writer.WriteLine($"        → 예상 예외: {exception}");
                    Console.WriteLine($"        → 예상 예외: {exception}");
                }
            }
        }

        // 결과 저장 및 종료 메시지 출력
        writer.Flush();
        exceptionWriter.Flush();
        Console.WriteLine("📄 결과 저장 완료: " + outputPath);
        Console.WriteLine("아무 키나 누르면 종료됩니다...");
        Console.ReadKey();
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
            Console.WriteLine($"{indent}🔄 내부 호출: {methodFullName}()");

            // 프레임워크 API 예외 추론
            var ns = innerSymbol.ContainingNamespace?.ToDisplayString();
            if (ns.StartsWith("System") || ns.StartsWith("Microsoft"))
            {
                var matchedDocs = _apiDocCache
                                                     .Where(kvp =>
                                                     {
                                                         var fullMethodSignature = kvp.Key;
                                                         var nameOnly = fullMethodSignature.Split('.').Last().Split('(')[0]; // 예: IndexOf
                                                         return nameOnly == methodName;
                                                     })
                                                     .Select(kvp => kvp.Value)
                                                     .ToList();

                if (matchedDocs.Count == 0)
                {

                    writer.WriteLine($"    🔧 {methodFullName}() - 문서화되지 않은 메서드");
                    Console.WriteLine($"    🔧 {methodFullName}() - 문서화되지 않은 메서드");
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
                            if (!methodExceptionList.Contains(exception.Key))
                            {
                                methodExceptionList.Add(exception.Key);
                            }

                            if (!exceptionList.Any(item => item.Key == exception.Key))
                            {
                                exceptionList.Add(exception);
                            }
                        }
                    }
                    else
                    {
                        writer.WriteLine("        📌 문서화된 예외 정보 없음");
                        Console.WriteLine("        📌 문서화된 예외 정보 없음");
                    }
                }

                foreach (var exception in exceptionList)
                {
                    writer.WriteLine($"        → 예상 예외: {exception.Key}");
                    Console.WriteLine($"        → 예상 예외: {exception.Key}");
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
}
