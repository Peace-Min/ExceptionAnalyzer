using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using System.Runtime.ConstrainedExecution;

namespace ExceptionAnalyzerLight
{
    internal class Program
    {
        // 🔍 예외 추론 사전
        private static readonly Dictionary<string, string> ExceptionMap = new()
        {
            { "Parse", "FormatException" },
            { "Convert", "FormatException / InvalidCastException" },
            { "File.Open", "FileNotFoundException / IOException" },
            { "File.ReadAllText", "FileNotFoundException / IOException / UnauthorizedAccessException" },
            { "Directory.GetFiles", "DirectoryNotFoundException / IOException" },
            { "HttpClient", "HttpRequestException" },
            { "JsonSerializer.Deserialize", "JsonException" },
            { "int.Parse", "FormatException / OverflowException" },
            { "DateTime.Parse", "FormatException" },
            { "XmlDocument.Load", "FileNotFoundException / XmlException" },

            // SQLite 관련
            { "SQLiteConnection.CreateCommand", "InvalidOperationException / ObjectDisposedException / SQLiteException" },
            { "SQLiteCommand.ExecuteReader", "InvalidOperationException / SQLiteException / DbException / ObjectDisposedException / TimeoutException" },
            { "SQLiteConnection.BeginTransaction", "InvalidOperationException / SQLiteException / ObjectDisposedException" },
            { "SQLiteConnection.Open", "InvalidOperationException / SQLiteException / ObjectDisposedException" },
            { "SQLiteConnection.Close", "SQLiteException / ObjectDisposedException" },
            { "SQLiteConnection.Dispose", "SQLiteException" },
            { "SQLiteCommand.ExecuteNonQuery", "InvalidOperationException / SQLiteException / ObjectDisposedException / TimeoutException" },
            { "SQLiteCommand.ExecuteScalar", "InvalidOperationException / SQLiteException / ObjectDisposedException / TimeoutException" },
            { "SQLiteCommand.Prepare", "InvalidOperationException / SQLiteException / ObjectDisposedException" },
            { "SQLiteDataReader.Read", "InvalidOperationException / SQLiteException / ObjectDisposedException" },

            // LINQ 계열
            { "Enumerable.Min", "InvalidOperationException / ArgumentNullException" },
            { "Enumerable.Max", "InvalidOperationException / ArgumentNullException" },
            { "Enumerable.FirstOrDefault", "ArgumentNullException" },
            { "Enumerable.Last", "InvalidOperationException / ArgumentNullException" },
            { "Enumerable.Where", "ArgumentNullException" },
            { "Enumerable.Select", "ArgumentNullException" },
            { "Enumerable.ElementAt", "ArgumentNullException / ArgumentOutOfRangeException" },
            { "Enumerable.ToArray", "ArgumentNullException" },
            { "Enumerable.ToList", "ArgumentNullException" },

            // Math 계열 - 예외 없음
            { "Math.Round", "ArgumentOutOfRangeException" },
            { "Math.Max", "None" },
            { "Math.Min", "None" },
            { "Math.Sqrt", "None" },
            { "Math.Pow", "None" },
            { "Math.Abs", "None" },
            { "Math.Ceiling", "None" },
            { "Math.Floor", "None" },
            { "Math.Truncate", "None" },
            { "Math.Sign", "None" },
            { "Math.Exp", "None" },
            { "Math.Log", "None" },
            { "Math.Log10", "None" },
            { "Math.Sin", "None" },
            { "Math.Cos", "None" },
            { "Math.Tan", "None" },
            { "Math.Asin", "None" },
            { "Math.Acos", "None" },
            { "Math.Atan", "None" },
            { "Math.Atan2", "None" },

            // String 관련
            { "String.EndsWith", "ArgumentNullException / ArgumentOutOfRangeException / CultureNotFoundException" },
            { "String.IsNullOrWhiteSpace", "None" },
            { "String.Format", "FormatException / ArgumentNullException" },
            { "String.IndexOf", "ArgumentNullException / ArgumentOutOfRangeException" },
            { "String.Substring", "ArgumentOutOfRangeException" },
            { "String.Trim", "None" },
            { "String.TrimEnd", "None" },

            // List, Array
            { "List.IndexOf", "ArgumentNullException" },
            { "IList.IndexOf", "ArgumentNullException" },
            { "List.Add", "None" },
            { "List.ToArray", "None" },
            { "Array.GetLength", "None" },

            // Reflection
            { "CustomAttributeExtensions.GetCustomAttribute", "ArgumentNullException / AmbiguousMatchException" },
            { "PropertyInfo.SetValue", "ArgumentException / TargetException / MethodAccessException / TargetInvocationException" },
            { "Activator.CreateInstance", "MissingMethodException / MemberAccessException / TargetInvocationException / TypeLoadException" },

            // Task / Thread
            { "Task.WhenAny", "ArgumentNullException" },
            { "Task.Delay", "ArgumentOutOfRangeException / TaskCanceledException" },
            { "Thread.Sleep", "ArgumentOutOfRangeException" },
            { "TaskCompletionSource.TrySetResult", "None" },

            // IO
            { "File.Copy", "IOException / UnauthorizedAccessException / ArgumentException / NotSupportedException / PathTooLongException" },
            { "File.Create", "IOException / UnauthorizedAccessException / ArgumentException / PathTooLongException" },
            { "File.Exists", "None" },
            { "TextWriter.WriteLine", "ObjectDisposedException / IOException" },

            // Encoding
            { "Encoding.GetString", "ArgumentNullException / ArgumentOutOfRangeException" },
            { "Encoding.GetBytes", "ArgumentNullException" },

            // Collection
            { "Collection.Add", "NotSupportedException" },
            { "Collection.Clear", "NotSupportedException" },

            // Dictionary
            { "Dictionary.ContainsKey", "ArgumentNullException" },
            { "Dictionary.Add", "ArgumentException / ArgumentNullException" },
            { "Dictionary.Remove", "ArgumentNullException" },

            // Diagnostics
            { "Debug.Fail", "SecurityException" },

            // WPF
            { "Window.Close", "InvalidOperationException" },
            { "MessageBox.Show", "None" },
            { "BackgroundWorker.ReportProgress", "InvalidOperationException" },

            // Monitor
            { "Monitor.Enter", "ArgumentNullException" },

            { "Console.WriteLine", "IOException / ObjectDisposedException" },
            { "DateTime.ToString", "FormatException / CultureNotFoundException" },
            { "SQLiteTransaction.Commit", "SQLiteException / InvalidOperationException / ObjectDisposedException" },
            { "JsonSerializer.Serialize", "NotSupportedException / InvalidOperationException / JsonException / ArgumentNullException" },
            { "Object.ToString", "None" }, // 단순한 오버라이드 기반, 일반적으로 예외 발생하지 않음
            
            { "StringBuilder.Append", "ArgumentNullException" }, // null 문자열 추가 시
            { "StringBuilder.ToString", "OutOfMemoryException" }, // 매우 드물지만 메모리 부족 시 발생

            { "AdornerLayer.GetAdornerLayer", "ArgumentNullException" }, // Visual이 null일 때
            { "AdornerLayer.Add", "ArgumentNullException" }, // Adorner가 null일 때
            { "AdornerLayer.Remove", "ArgumentNullException" }, // 제거 시 null 전달

            { "DragDrop.DoDragDrop", "InvalidOperationException / ArgumentNullException" }, // Element나 Data가 null일 경우, DragDrop 초기화 문제 등

            { "DataObject.SetData", "ArgumentNullException / ArgumentException" }, // 형식이 null이거나 잘못된 데이터 유형일 때

            { "List.Sort", "InvalidOperationException / ArgumentException" }, // IComparer에서 예외 발생, 비교 불가능 항목

            { "ArrayList.Contains", "None" }, // 비교 대상이 null이어도 예외 없음
            { "Type.GetProperties", "AmbiguousMatchException / SecurityException" },
            { "Enumerable.OrderBy", "ArgumentNullException" },
            { "CancellationToken.ThrowIfCancellationRequested", "OperationCanceledException" },
            { "Guid.GetHashCode", "None" },
            { "Guid.NewGuid", "None" },
            { "Random.NextDouble", "None" },
            { "CancellationTokenSource.Cancel", "ObjectDisposedException" },
            { "Dictionary.TryGetValue", "ArgumentNullException" },
            { "Double.IsNaN", "None" },
            { "Exception.ToString", "None" },
            { "Collection.RemoveAt", "ArgumentOutOfRangeException / NotSupportedException" },
            { "Collection.IndexOf", "ArgumentNullException / NotSupportedException" },
            { "DrawingContext.DrawRectangle", "ArgumentNullException / InvalidOperationException" },
            { "DrawingContext.DrawLine", "ArgumentNullException / InvalidOperationException" },
            { "DrawingContext.DrawText", "ArgumentNullException / InvalidOperationException" },
            { "DrawingContext.DrawImage", "ArgumentNullException / InvalidOperationException" },
            { "DrawingContext.DrawDrawing", "ArgumentNullException / InvalidOperationException" },

            // IO 및 경로 관련
            { "Directory.Exists", "None" },
            { "Directory.CreateDirectory", "IOException / UnauthorizedAccessException / ArgumentException / PathTooLongException" },
            { "StreamWriter.Flush", "ObjectDisposedException / IOException" },
            { "StreamWriter.Close", "ObjectDisposedException / IOException" },
            { "Path.GetFullPath", "ArgumentException / SecurityException / NotSupportedException" },
            { "File.GetAccessControl", "UnauthorizedAccessException / ArgumentException / IOException / NotSupportedException" },
            { "File.Delete", "UnauthorizedAccessException / ArgumentException / IOException / PathTooLongException" },

            // 보안 및 권한
            { "CommonObjectSecurity.GetAccessRules", "PrivilegeNotHeldException / UnauthorizedAccessException" },
            { "WindowsIdentity.GetCurrent", "SecurityException" },

            // 기타 BCL
            { "String.IsNullOrEmpty", "None" },
            { "Enum.HasFlag", "ArgumentException" },
            { "System.Byte.ToString", "None" },
            { "System.UInt16.ToString", "None" },
            { "System.Collections.Generic.Queue.Dequeue", "InvalidOperationException" },
            { "System.IO.Ports.SerialPort.Open", "InvalidOperationException / IOException / UnauthorizedAccessException" },
            { "System.Threading.Thread.Start", "ThreadStateException / OutOfMemoryException" },
            { "System.IO.Ports.SerialPort.Close", "IOException" },
            { "System.EventHandler.Invoke", "TargetInvocationException" },
            { "System.IO.Ports.SerialPort.Read", "InvalidOperationException / TimeoutException" },
            { "System.Buffer.BlockCopy", "ArgumentException / ArgumentOutOfRangeException / ArgumentNullException" },
            { "System.Collections.Generic.List.RemoveAt", "ArgumentOutOfRangeException" },
            { "System.Net.Sockets.TcpClient.Connect", "SocketException / ArgumentNullException / InvalidOperationException" },
            { "System.Net.Sockets.TcpClient.GetStream", "InvalidOperationException" },
            { "System.Threading.Tasks.Task.Run", "ArgumentNullException" },
            { "System.IO.StreamReader.Close", "None" },
            { "System.IO.Stream.Close", "None" },
            { "System.Net.Sockets.TcpClient.Close", "None" },
            { "System.Array.Copy", "ArgumentException / ArgumentOutOfRangeException / ArgumentNullException" },
            { "System.IO.Stream.WriteAsync", "ObjectDisposedException / NotSupportedException / InvalidOperationException" },
            { "System.IO.Stream.FlushAsync", "ObjectDisposedException / NotSupportedException / InvalidOperationException" },
            { "System.Net.Sockets.NetworkStream.Read", "IOException / ObjectDisposedException / ArgumentNullException / ArgumentOutOfRangeException" },
            { "System.Collections.Generic.List.Remove", "None" },
            { "System.Net.Sockets.TcpListener.AcceptTcpClient", "SocketException / ObjectDisposedException" },
            { "System.IO.MemoryStream.Write", "NotSupportedException / ObjectDisposedException" },
            { "System.IO.MemoryStream.Seek", "IOException / NotSupportedException / ObjectDisposedException" },
            { "System.IO.MemoryStream.Read", "NotSupportedException / ObjectDisposedException" },

            { "Microsoft.Office.Interop.Excel.Workbooks.Open", "COMException / ArgumentException / InvalidCastException" },
            { "Microsoft.Office.Interop.Excel._Workbook.Close", "COMException" },
            { "Microsoft.Office.Interop.Excel._Application.Quit", "COMException" },
            { "System.Net.NetworkInformation.Ping.Send", "PingException / InvalidOperationException / ArgumentNullException" },

            { "System.Reflection.Assembly.GetTypes", "ReflectionTypeLoadException" },
            { "System.Reflection.Assembly.GetExecutingAssembly", "None" },

            { "System.Action.Invoke", "NullReferenceException / TargetInvocationException" },

            { "System.Net.IPAddress.ToString", "None" },
            { "System.Net.Sockets.NetworkStream.Write", "IOException / ObjectDisposedException / NotSupportedException" },
            { "System.Net.Sockets.NetworkStream.Flush", "IOException / ObjectDisposedException / NotSupportedException" },

            { "System.Int32.ToString", "None" },

            { "System.Collections.Concurrent.ConcurrentDictionary.TryAdd", "ArgumentNullException" },

            { "System.Net.Sockets.TcpListener.Stop", "SocketException / ObjectDisposedException" },

            { "System.Threading.Thread.Abort", "ThreadStateException / SecurityException" },

            { "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Serialize", "SerializationException / SecurityException" },
            { "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize", "SerializationException / SecurityException / ArgumentNullException" },

            { "System.IO.MemoryStream.ToArray", "ObjectDisposedException" },

            { "System.Linq.Enumerable.Cast", "InvalidCastException / ArgumentNullException" },

            { "System.Enum.GetValues", "ArgumentException" },

            { "System.IO.Path.GetFileNameWithoutExtension", "ArgumentException" },

            { "System.Collections.Generic.List.Contains", "ArgumentNullException" },

            { "System.Linq.Enumerable.Range", "ArgumentOutOfRangeException" },
            { "System.Linq.Enumerable.First", "InvalidOperationException" },

            { "System.Windows.Threading.Dispatcher.BeginInvoke", "ArgumentNullException / InvalidOperationException" },

            { "System.Collections.Generic.List.Find", "ArgumentNullException" },
            { "System.String.Equals", "None" },

            { "System.Collections.ObjectModel.Collection.Insert", "ArgumentOutOfRangeException / ArgumentNullException" },

            { "System.IO.FileStream.Write", "IOException / ObjectDisposedException / NotSupportedException" },
        };

        // 📘 예외 설명 사전
        private static readonly Dictionary<string, string> ExceptionDescriptionMap = new()
        {
            { "FormatException", "입력 문자열의 형식이 잘못되었을 때 발생합니다." },
            { "InvalidCastException", "형식 변환이 유효하지 않을 때 발생합니다." },
            { "FileNotFoundException", "지정된 파일을 찾을 수 없을 때 발생합니다." },
            { "IOException", "입출력 작업 중 오류가 발생했을 때 발생합니다." },
            { "UnauthorizedAccessException", "파일 또는 디렉터리에 대한 권한이 없을 때 발생합니다." },
            { "DirectoryNotFoundException", "지정한 디렉터리를 찾을 수 없을 때 발생합니다." },
            { "HttpRequestException", "HTTP 요청 중 문제가 발생했을 때 발생합니다." },
            { "JsonException", "JSON 파싱 또는 직렬화/역직렬화 오류가 발생했을 때 발생합니다." },
            { "OverflowException", "숫자 형식에서 허용된 범위를 초과할 때 발생합니다." },
            { "XmlException", "XML 문서를 구문 분석하는 중 오류가 발생했을 때 발생합니다." },
            { "InvalidOperationException", "현재 객체 상태에서 작업이 유효하지 않을 때 발생합니다." },
            { "ObjectDisposedException", "이미 해제(disposed)된 객체를 사용할 때 발생합니다." },
            { "SQLiteException", "SQLite 작업 중 오류가 발생했을 때 발생합니다." },
            { "DbException", "데이터베이스 관련 작업 중 오류가 발생했을 때 발생합니다." },
            { "TimeoutException", "작업이 지정된 시간 내에 완료되지 않았을 때 발생합니다." },
            { "ArgumentNullException", "필수 인수에 null이 전달되었을 때 발생합니다." },
            { "ArgumentOutOfRangeException", "인수 값이 허용 범위를 벗어났을 때 발생합니다." },
            { "CultureNotFoundException", "지정한 문화권 정보가 잘못되었거나 사용할 수 없을 때 발생합니다." },
            { "SecurityException", "보안 제약 조건을 위반했을 때 발생합니다." },
            { "ArgumentException", "인수에 잘못된 값이 전달되었을 때 발생합니다." },
            { "NotSupportedException", "해당 작업이 지원되지 않을 때 발생합니다." },
            { "MissingMethodException", "호출하려는 생성자나 메서드가 존재하지 않을 때 발생합니다." },
            { "MemberAccessException", "비공개 멤버 등에 접근하려고 할 때 발생합니다." },
            { "TargetInvocationException", "리플렉션으로 호출된 메서드 내에서 예외가 발생했을 때 래핑되어 발생합니다." },
            { "TypeLoadException", "형식을 로드할 수 없을 때 발생합니다." },
            { "TargetException", "잘못된 대상 객체로 리플렉션 작업을 수행하려 할 때 발생합니다." },
            { "TaskCanceledException", "비동기 작업이 취소되었을 때 발생합니다." },
            { "OutOfMemoryException", "시스템에 사용 가능한 메모리가 부족할 때 발생합니다." },
            { "AmbiguousMatchException", "특성 또는 멤버 검색 시 다중 일치 항목이 있을 때 발생합니다." },
            { "MethodAccessException", "보호 수준 또는 접근 제한으로 인해 메서드에 접근할 수 없을 때 발생합니다." },
            { "PathTooLongException", "파일 또는 디렉터리 경로가 시스템에서 허용하는 최대 길이를 초과했을 때 발생합니다." },
            { "OperationCanceledException", "작업이 취소되었을 때 발생합니다." },
            { "PrivilegeNotHeldException", "필요한 보안 권한이 없는 경우 발생합니다." },
            { "ThreadStateException", "스레드가 잘못된 상태에서 작업을 수행하려고 할 때 발생합니다. 예: 이미 시작된 스레드를 다시 시작하려고 시도한 경우." },
            { "SocketException", "소켓 작업 중 오류가 발생했을 때 발생합니다. 네트워크 오류, 연결 실패, 포트 접근 불가 등 다양한 원인이 있습니다." },
            { "COMException", "COM 구성 요소에서 오류가 발생했을 때 발생합니다." },
            { "PingException", "Ping 요청을 보낼 수 없거나 응답을 받을 수 없을 때 발생합니다." },
            { "ReflectionTypeLoadException", "어셈블리에서 하나 이상의 형식을 로드하지 못했을 때 발생합니다." },
            { "NullReferenceException", "객체 참조가 null인 상태에서 해당 객체의 멤버에 접근할 때 발생합니다." },
            { "SerializationException", "직렬화 또는 역직렬화 작업 중 문제가 발생했을 때 발생합니다." },
            { "None"," "}

        };

        private static async Task Main(string[] args)
        {
            // 1. 분석할 디렉토리 지정 
            // ※ 분석 대상 프로젝트 경로 설정※
            var targetDirectory = string.Empty; 
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
                    if (message.Contains("RAEChartControl")) {; }

                    // 9-3. 각 호출에 대해 의미 정보 추출
                    foreach (var call in methodCalls)
                    {
                        // 호출된 메서드의 심볼 정보 추출
                        var symbolInfo = semanticModel.GetSymbolInfo(call);
                        var methodSymbol = symbolInfo.Symbol as IMethodSymbol;

                        // 후보 목록에서 대체 추출
                        if (methodSymbol == null)
                        {
                            methodSymbol = symbolInfo.CandidateSymbols.FirstOrDefault() as IMethodSymbol;
                        }

                        if (methodSymbol == null) continue;

                        var ns = methodSymbol.ContainingNamespace?.ToDisplayString();
                        if (string.IsNullOrEmpty(ns)) continue;

                        var methodFullName = $"{methodSymbol.ContainingNamespace}.{methodSymbol.ContainingType.Name}.{methodSymbol.Name}";


                        if (ns.StartsWith("System") || ns.StartsWith("Microsoft"))
                        {
                            writer.WriteLine($"    🔧 {methodFullName}()");
                            Console.WriteLine($"    🔧 {methodFullName}()");

                            // 예외 추론
                            var keyMatch = ExceptionMap
                                .Where(kv => methodFullName.Contains(kv.Key, StringComparison.OrdinalIgnoreCase)
                                          || methodSymbol.Name.Contains(kv.Key, StringComparison.OrdinalIgnoreCase))
                                .Select(kv => kv.Value)
                                .Distinct()
                                .ToList();

                            if (keyMatch.Any())
                            {
                                foreach (var exception in keyMatch)
                                {
                                    var description = string.Join(" | ", exception
                                                            .Split(new[] { ',', '/' })
                                                            .Select(ex =>
                                                            {
                                                                var trimmed = ex.Trim();
                                                                return ExceptionDescriptionMap.TryGetValue(trimmed, out var desc)
                                                                ? $"{trimmed} - {desc}"
                                                                : $"{trimmed} - (설명 없음)";
                                                            }));
                                    writer.WriteLine($"        → 예상 예외: {description}");
                                    Console.WriteLine($"        → 예상 예외: {description}");

                                    if (description.Contains("설명 없음"))
                                    {
                                        exceptionWriter.WriteLine($"    🔧 {methodFullName}()");
                                        exceptionWriter.WriteLine($"        📘  예외 설명 사전에 등록 필요: {exception}");
                                    }
                                }
                            }
                            else
                            {
                                writer.WriteLine($"        📌 예외 추론 컬렉션에 등록 필요: {methodSymbol.Name}");
                                Console.WriteLine($"        📌 예외 추론 컬렉션에 등록 필요: {methodSymbol.Name}");
                                exceptionWriter.WriteLine($"    🔧 {methodFullName}()");
                                exceptionWriter.WriteLine($"        📌 예외 추론 컬렉션에 등록 필요: {methodSymbol.Name}");
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

                var innerFullName = $"{innerSymbol.ContainingNamespace}.{innerSymbol.ContainingType.Name}.{innerSymbol.Name}";

                writer.WriteLine($"{indent}🔄 내부 호출: {innerFullName}()");
                Console.WriteLine($"{indent}🔄 내부 호출: {innerFullName}()");

                // 프레임워크 API 예외 추론
                if (innerSymbol.ContainingNamespace?.ToDisplayString().StartsWith("System") == true)
                {
                    var keyMatch = ExceptionMap
                        .Where(kv => innerFullName.Contains(kv.Key, StringComparison.OrdinalIgnoreCase)
                                  || innerSymbol.Name.Contains(kv.Key, StringComparison.OrdinalIgnoreCase))
                        .Select(kv => kv.Value)
                        .Distinct()
                        .ToList();

                    if (keyMatch.Any())
                    {
                        foreach (var exception in keyMatch)
                        {
                            var description = string.Join(" | ", exception
                                                    .Split(new[] { ',', '/' })
                                                    .Select(ex =>
                                                    {
                                                        var trimmed = ex.Trim();
                                                        return ExceptionDescriptionMap.TryGetValue(trimmed, out var desc)
                                                            ? $"{trimmed} - {desc}"
                                                            : $"{trimmed} - (설명 없음)";
                                                    }));

                            writer.WriteLine($"{indent}    → 예상 예외: {description}");
                            Console.WriteLine($"{indent}    → 예상 예외: {description}");

                            if (description.Contains("설명 없음"))
                            {
                                exceptionWriter.WriteLine($"{indent}🔧 {innerFullName}()");
                                exceptionWriter.WriteLine($"{indent}    📘  예외 설명 사전에 등록 필요: {exception}");
                            }
                        }
                    }
                    else
                    {
                        writer.WriteLine($"{indent}    📌 예외 추론 컬렉션에 등록 필요: {innerSymbol.Name}");
                        exceptionWriter.WriteLine($"{indent}🔧 {innerFullName}()");
                        exceptionWriter.WriteLine($"{indent}    📌 예외 추론 컬렉션에 등록 필요: {innerSymbol.Name}");
                    }
                }
                else
                {
                    // 중첩 사용자 정의 메서드면 재귀 호출
                    var nextMethodSyntax = innerSymbol.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() as MethodDeclarationSyntax;
                    if (nextMethodSyntax != null && depth < 5) // 최대 재귀 제한
                    {
                        AnalyzeInternalMethod(nextMethodSyntax, semanticModel, writer, exceptionWriter, innerFullName, depth + 1);
                    }
                }
            }
        }
    }
}

