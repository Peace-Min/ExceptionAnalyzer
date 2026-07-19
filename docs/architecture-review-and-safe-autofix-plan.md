# ExceptionAnalyzer 아키텍처 검수 및 제한적 자동수정 전환 계획

- 상태: 검수 완료 / 구현 대기
- 기준일: 2026-07-19
- 대상 저장소: `Peace-Min/ExceptionAnalyzer`
- 대상 기능: C# `try-catch` 분석, 예외 후보 추론, 제한적 소스 자동수정
- 추적 이슈: [#1 ExceptionAnalyzer를 누락 감지형 분석기 + 안전 제한 자동수정기로 재설계](https://github.com/Peace-Min/ExceptionAnalyzer/issues/1)

## 1. 문서 목적

이 문서는 ExceptionAnalyzer의 현재 구조가 다음 목표를 충족하는지 검수하고, 실제로 운영 가능한 "분석기 + 제한적 자동수정기"로 전환하기 위한 기준을 정의한다.

1. `.sln`이 있으면 solution/project 정보를 적극 활용한다.
2. `.sln`이 없어도 `.csproj` 또는 소스 기반으로 가능한 범위까지 분석한다.
3. 대상 프로젝트가 빌드되지 않거나 Debug/Release 출력이 없어도 분석 가능한 경로를 제공한다.
4. 프로젝트 및 소스 누락을 성공으로 숨기지 않는다.
5. 불완전한 예외 추론 결과로 소스 동작을 임의 변경하지 않는다.
6. 자동수정은 검증 가능한 제한된 조건에서만 허용한다.

## 2. 최종 판단

현재 구현은 **분석용 프로토타입으로는 조건부 사용 가능하지만 자동수정 도구로는 승인할 수 없다.**

다만 현재 Roslyn 및 `MSBuildWorkspace` 도입 코드는 재사용할 수 있다. 아래에 정의한 입력 해석, coverage, 의미 분석, 신뢰도 모델, 변경 안전성 및 테스트 체계를 구현하면 현실적인 **분석기 + 제한적 자동수정기 MVP**는 가능하다.

일반 C# 프로그램에서 발생 가능한 모든 런타임 예외를 정적으로 완전하게 열거하는 것은 보장할 수 없다. 따라서 이 도구가 보장해야 하는 것은 "예외 목록의 완전성"이 아니라 다음 항목이다.

- 선택한 분석 범위가 누락 없이 처리되었는지 여부
- 각 예외 후보가 어떤 근거로 도출되었는지
- 해석되지 않은 호출이나 프로젝트가 있는지
- 현재 결과로 자동수정을 허용할 수 있는지

## 3. 검수 방법 및 확인 결과

검수는 소스 및 Git diff 정적 검토, 빌드, 내장 selftest, 솔루션 preview와 별도 임시 fixture로 수행했다.

확인 결과:

- `dotnet build ExceptionAnalyzer/ExceptionAnalyzer.csproj --no-restore`: 성공
- nullable 경고 3건 존재
- `--selftest-xml`: PASS
- `--selftest-fix`: PASS
- `dotnet test ExceptionAnalyzer.sln --no-build`: 테스트 프로젝트가 없어 실행된 테스트 없음
- 솔루션 preview: 변경 후보 9건, 수동검토 5건, 컴파일 롤백 0건
- 별도 fixture에서 다음 문제를 재현함
  - ProjectReference를 경유한 호출 분석 시 `SyntaxTree는 컴파일의 일부가 아닙니다` 예외
  - 중첩 try 2건을 수정했다고 보고하지만 실제 child 수정이 유실됨
  - 기존 오류와 ID가 같은 신규 컴파일 오류가 검증을 통과함
  - 전체 파일 포맷 과정에서 줄바꿈이 혼합됨

내장 selftest가 통과하는 사실은 현재 자동수정의 안전성을 의미하지 않는다. selftest는 기존 `LogUtil.Error(ex)` 본문을 삭제하고 `Debug.WriteLine(ex)`로 변경하는 동작을 정상으로 승인하고 있다.

## 4. 현재 실행 모델

### 4.1 입력별 동작

| 입력 | Analyze | Fix | 현재 문제 |
|---|---|---|---|
| 명시적 `.sln` | `MSBuildWorkspace` 사용 | `MSBuildWorkspace` 사용 | 부분 로드 및 진단을 성공으로 숨길 수 있음 |
| top-level `.sln`이 정확히 하나인 폴더 | solution 모드 | solution 모드 | nested solution을 발견하지 않음 |
| 명시적 `.csproj` | 실패 | 실패 | 프로젝트 직접 입력 미지원 |
| `.sln`이 없는 폴더 | 실패 | 모든 `.cs` 재귀 fallback | analyze/fix 동작 불일치 |
| `.sln`이 여러 개인 폴더 | 실패 | 모든 `.cs` 재귀 fallback | 선택하지 않은 프로젝트까지 수정 가능 |
| MSBuild/restore가 불완전한 solution | 일부 진행 가능 | 일부 진행 가능 | 누락을 구조화하지 않고 성공 종료 가능 |

### 4.2 DLL 및 빌드 출력 사용 여부

Solution 경로에서는 대상 프로젝트 DLL을 역분석하지 않는다. `MSBuildWorkspace`가 프로젝트 파일, 소스 문서, 참조 및 컴파일 옵션을 평가하여 Roslyn `Compilation`을 만든다. 따라서 Debug/Release 출력 DLL이 없어도 SDK, target pack 및 restore assets가 준비되어 있으면 분석할 수 있다.

반면 source-only fallback은 다음 방식이다.

- 각 `.cs` 파일을 개별 compilation으로 생성한다.
- 대상 폴더의 `bin/Debug` 바로 아래 DLL만 참조한다.
- .NET Framework 4.7.2 reference assembly를 강제로 추가한다.

이 경로에서는 다른 소스 파일, project reference, NuGet reference, `DefineConstants`, target framework 및 linked item 문맥이 사라지므로 정확한 의미 분석을 기대할 수 없다.

## 5. 발견 사항

### P0-01. solution 선택 실패 시 수정 범위가 폴더 전체로 확대됨

근거:

- `TryResolveSingleSolutionPath`는 `.sln` 0개와 2개 이상을 모두 `null`로 반환한다.
- `RunFix`는 이 두 경우를 구분하지 않고 `SearchOption.AllDirectories`로 모든 `.cs`를 수집한다.
- apply 모드에서는 해당 파일을 직접 덮어쓴다.

영향:

- 여러 solution이 있는 저장소에서 어느 solution도 선택하지 않은 채 전체 저장소가 수정될 수 있다.
- `obj`, 생성 코드, vendor 코드 및 분석 대상이 아닌 프로젝트가 포함될 수 있다.
- analyze는 실패하지만 fix는 광역 수정으로 진행하므로 사용자 예측과 다르게 동작한다.

필수 조치:

- 입력 해석을 단일 `TargetResolver`로 통합한다.
- `.sln` 복수 발견은 명시적 선택 오류로 종료한다.
- `Partial` 또는 `SyntaxOnly` 상태에서는 source apply를 금지한다.

관련 코드: [`Program.cs`](../ExceptionAnalyzer/Program.cs#L118), [`Program.cs`](../ExceptionAnalyzer/Program.cs#L930), [`Program.cs`](../ExceptionAnalyzer/Program.cs#L938)

### P0-02. 원래 catch의 동작, filter 및 주석이 삭제됨

근거:

- 단일 호출문 catch를 수정 안전 대상으로 판정한다.
- 치환 시 원본 catch clause를 버리고 모든 catch 본문을 `Debug.WriteLine(ex)`로 재생성한다.
- WPF는 preview 단계 없이 `apply: true`를 호출한다.

영향:

- `Log.Error(ex)`, rollback, metric, telemetry 등 원래 side effect가 사라진다.
- `catch (...) when (...)`의 filter가 제거되어 예외 전파 의미가 바뀐다.
- 빈 broad catch를 일부 구체 예외로 좁히면 이전에 삼키던 미추론 예외가 외부로 전파된다.
- 컴파일 성공만으로는 이러한 런타임 의미 변경을 검출할 수 없다.

필수 조치:

- 현재 GUI apply 기능을 우선 차단하고 preview를 기본값으로 변경한다.
- filter 또는 non-empty body가 있는 catch는 기본적으로 suggestion-only로 분류한다.
- broad fallback 제거는 명시적 사용자 승인 없이는 허용하지 않는다.

관련 코드: [`Program.cs`](../ExceptionAnalyzer/Program.cs#L755), [`Program.cs`](../ExceptionAnalyzer/Program.cs#L764), [`MainWindow.xaml.cs`](../ExceptionAnalyzer/MainWindow.xaml.cs#L56)

### P1-01. ProjectReference를 건너가는 호출에서 전체 분석이 중단됨

소비 프로젝트의 `Compilation`으로 참조 프로젝트에 속한 `SyntaxTree`의 `SemanticModel`을 요청한다. 해당 트리는 소비 프로젝트 compilation의 일부가 아니므로 `ArgumentException`이 발생한다.

필수 조치:

- solution 전체의 `DocumentId → ProjectId → Compilation/SemanticModel` 매핑을 관리한다.
- source definition이 다른 프로젝트에 있으면 해당 document의 semantic model을 사용한다.
- call graph node는 메서드 심볼뿐 아니라 프로젝트 문맥을 함께 보관한다.

관련 코드: [`Program.cs`](../ExceptionAnalyzer/Program.cs#L348), [`Program.cs`](../ExceptionAnalyzer/Program.cs#L460)

### P1-02. 예외 추론이 누락과 오탐을 동시에 생성함

현재는 주로 `InvocationExpressionSyntax`만 수집한다.

누락 대상:

- `throw` statement 및 throw expression
- object creation과 constructor
- property/indexer getter 및 setter
- operator와 conversion
- iterator/enumerator 및 implicit `Dispose`
- constructor, accessor, local function 등 `MethodDeclarationSyntax` 이외의 source body
- global namespace 사용자 메서드

오탐 대상:

- 실행되지 않은 lambda/local function 본문
- 내부 catch에서 이미 처리된 nested try 호출
- 실제 실행 경로와 관계없는 분기
- await되지 않은 async 호출과 실행되지 않은 iterator body

추가 문제:

- 순환 방문 집합 없이 depth 5로만 종료한다.
- `System*`, `Microsoft*` namespace prefix로 framework 여부를 판별한다.
- `SystemCompany` 같은 사용자 namespace가 framework로 오분류될 수 있다.

필수 조치:

- `IOperation` 및 필요한 범위에서 Control Flow Graph를 사용한다.
- source method summary를 symbol/project 단위로 캐시한다.
- cycle-safe worklist 또는 SCC/fixpoint 방식으로 호출 그래프를 계산한다.
- exception source와 전파 경로를 결과에 기록한다.

관련 코드: [`Program.cs`](../ExceptionAnalyzer/Program.cs#L269), [`Program.cs`](../ExceptionAnalyzer/Program.cs#L397)

### P1-03. 중첩 try 수정 수와 실제 결과가 다름

부모와 자식 `TryStatementSyntax`를 동시에 `ReplaceNodes`에 전달하면서 부모 callback이 이미 변경된 `rewrittenNode`를 무시한다. 부모 replacement가 원본 block을 다시 사용하므로 child 변경이 유실된다.

또한 outer try 분석이 inner try의 모든 invocation을 포함하여 inner catch에서 처리된 예외를 outer 후보에 추가한다.

필수 조치:

- 분석 대상 region에서 nested function 및 처리 완료된 nested try 경계를 구분한다.
- rewrite는 `DocumentEditor` 또는 `SyntaxEditor`를 사용해 단계적으로 적용한다.
- 최종 syntax tree에서 실제 변경된 node 수를 다시 계산한다.

관련 코드: [`Program.cs`](../ExceptionAnalyzer/Program.cs#L796), [`Program.cs`](../ExceptionAnalyzer/Program.cs#L848)

### P1-04. 동일 diagnostic ID의 신규 오류를 허용함

현재 검증은 원본 compilation의 오류 ID를 `HashSet`으로 만든다. 원본 어딘가에 같은 ID가 하나라도 있으면 변경 후 새 위치에서 증가한 오류도 기존 오류로 취급한다.

필수 조치:

- 진단을 `(Id, Severity, FilePath, Span, Message)` 및 개수로 비교한다.
- 모든 변경을 하나의 `Solution` snapshot에 적용한 뒤 영향받는 프로젝트 전체를 재컴파일한다.
- baseline이 빌드 불가라면 신규 진단 증가가 없음을 검증하되 자동 apply는 기본 차단한다.

관련 코드: [`Program.cs`](../ExceptionAnalyzer/Program.cs#L856), [`Program.cs`](../ExceptionAnalyzer/Program.cs#L861)

### P1-05. 예외 문서가 .NET Framework 4.7.2 한국어 팩에 고정됨

문제:

- 대상 target framework와 무관하게 `v4.7.2/ko` XML을 먼저 읽는다.
- 해당 language pack이 없으면 solution을 열기 전에 실패한다.
- .NET 6/8/9 신규 API와 NuGet/third-party XML을 반영하지 않는다.
- 문서화된 exception 목록은 실제 발생 가능한 예외의 완전 목록이 아니다.
- runtime Roslyn Workspaces 4.0.1은 현대 C# 프로젝트 분석 범위와 차이가 있다.

필수 조치:

- 현재 compilation의 metadata reference 및 target framework reference pack에 연결된 documentation provider를 사용한다.
- project 및 package XML documentation을 함께 조회한다.
- XML 정보는 `Documented` provenance로 표시하고 완전성 근거로 사용하지 않는다.
- 지원할 C# language version과 Roslyn 패키지 버전을 명시하고 갱신한다.

관련 코드: [`Program.cs`](../ExceptionAnalyzer/Program.cs#L26), [`Program.cs`](../ExceptionAnalyzer/Program.cs#L146), [`ExceptionAnalyzer.csproj`](../ExceptionAnalyzer/ExceptionAnalyzer.csproj#L15)

### P1-06. Workspace 부분 실패와 문서 누락을 성공으로 숨김

`WorkspaceFailed`는 로그만 남기며 다음 상태를 구조화하지 않는다.

- solution에서 발견된 프로젝트 수
- 성공적으로 로드된 프로젝트 수
- compilation 생성 실패 프로젝트
- project document와 물리 `.cs`의 차이
- symbol resolution 실패 건수
- workspace/restore/targeting pack 진단

필수 조치:

- `WorkspaceLoadResult`에 프로젝트, 문서, 진단 및 fallback 상태를 기록한다.
- 누락이 존재하면 전체 결과를 `Partial`로 표시한다.
- CLI는 partial 결과에 별도 exit code를 반환한다.
- 자동수정 eligibility는 coverage 결과를 필수 입력으로 사용한다.

관련 코드: [`Program.cs`](../ExceptionAnalyzer/Program.cs#L130), [`Program.cs`](../ExceptionAnalyzer/Program.cs#L202)

### P2-01. linked file, multi-target 및 conditional compilation이 안전하지 않음

- 동일 physical file을 여러 프로젝트가 포함하면 각 프로젝트의 stale snapshot이 순차적으로 파일을 덮을 수 있다.
- linked file이 solution root 밖에 있어도 직접 수정한다.
- multi-target 및 `#if` 구성별 분석·교차검증 정책이 없다.
- solution 경로에서는 generated document가 빠질 수 있고 source fallback에서는 `obj/**/*.cs`가 반대로 포함될 수 있다.

필수 조치:

- canonical physical path로 문서를 그룹화한다.
- 분석은 project context별로 수행하되 수정안 충돌을 감지한다.
- solution root 밖 파일은 별도 승인 대상으로 분리한다.
- TFM/configuration별 coverage를 보고한다.
- generated code는 기본 수정 금지로 설정한다.

### P2-02. 파일 전체 포맷, 인코딩 및 원자성 문제

- 하나의 catch 변경 후 문서 전체를 기본 `AdhocWorkspace` 옵션으로 format한다.
- 원래 encoding, BOM, line ending 및 editorconfig를 보존하지 않는다.
- 파일을 직접 덮어쓰며 전체 작업 transaction이 없다.

필수 조치:

- 변경 node에만 format annotation을 적용한다.
- 원본 `SourceText.Encoding`과 line ending을 보존한다.
- 전체 변경을 메모리에서 검증한 후 임시 파일과 atomic replace를 사용한다.
- 일부 파일 실패 시 앞선 파일만 변경된 상태가 남지 않도록 transaction 경계를 둔다.

관련 코드: [`Program.cs`](../ExceptionAnalyzer/Program.cs#L852), [`Program.cs`](../ExceptionAnalyzer/Program.cs#L879)

### P2-03. UI/CLI 정책 및 동시성 불일치

- CLI fix는 기본 preview이지만 GUI는 즉시 apply한다.
- UI 버튼 중복 클릭 방지가 없다.
- static cache와 static `Log`가 동시 실행 간 공유된다.
- `WinExe` 프로젝트에 CLI 진입점이 함께 있어 배포 및 출력 동작이 불명확하다.

필수 조치:

- Analyze → Preview → Apply를 명시적 단계로 분리한다.
- 작업 중 UI action을 비활성화하고 cancellation을 지원한다.
- Core service를 instance 기반으로 만들고 request별 상태를 분리한다.
- console CLI와 WPF frontend를 별도 프로젝트로 분리한다.

### P2-04. 테스트 및 문서 체계 부족

- 실제 test project가 없다.
- selftest가 production `Program` 안에 포함되어 있다.
- solution/MSBuild 경로를 검증하는 자동 테스트가 없다.
- README는 프로젝트 폐기 문구, .NET 6 설명 및 현재와 다른 ExceptionMap 구조를 포함한다.

필수 조치:

- Core unit test와 fixture integration test를 분리한다.
- README를 현재 제품 경계와 실행 방법에 맞게 갱신한다.
- JSON 또는 SARIF 같은 기계 판독 가능한 결과 형식을 추가한다.

## 6. 현실적인 제품 범위

### 6.1 보장 가능한 기능

- broad catch, bare catch, empty catch 탐지
- solution/project/source별 분석 coverage 보고
- 프로젝트 내부 호출 및 metadata API에서 확인된 예외 후보 수집
- 예외 후보별 출처와 호출 경로 표시
- catch 후보와 수정 diff 생성
- 명시적 승인 이후 제한적인 patch 적용
- 변경된 solution snapshot 컴파일 및 테스트 실행

### 6.2 보장할 수 없는 기능

- 모든 런타임 예외의 완전한 정적 열거
- reflection, native interop, dynamic dispatch 및 문서화되지 않은 외부 동작의 완전한 추론
- 불완전 분석 결과를 기반으로 한 broad catch의 무조건적 안전 제거
- 컴파일 성공만으로 런타임 동작 동일성을 증명하는 것

## 7. 목표 아키텍처

```text
ExceptionAnalyzer.Core
├─ Targeting
│  ├─ TargetResolver
│  ├─ SolutionWorkspaceLoader
│  ├─ ProjectWorkspaceLoader
│  └─ SyntaxFallbackLoader
├─ Coverage
│  ├─ WorkspaceLoadResult
│  ├─ SourceInventory
│  └─ CompletenessEvaluator
├─ Analysis
│  ├─ OperationCollector
│  ├─ CallGraphBuilder
│  ├─ ExceptionSummaryEngine
│  ├─ ExceptionKnowledgeProvider
│  └─ CatchDiagnosticEngine
├─ Fixing
│  ├─ FixEligibilityEvaluator
│  ├─ CodeFixPlanner
│  ├─ SolutionChangeValidator
│  └─ AtomicChangeApplier
└─ Reporting
   ├─ MarkdownReporter
   ├─ JsonReporter
   └─ SarifReporter

ExceptionAnalyzer.Cli
ExceptionAnalyzer.Wpf
ExceptionAnalyzer.Tests
```

`Program`, CLI 및 WPF는 동일한 Core request/result 모델을 사용해야 한다. UI와 CLI에 별도의 분석 알고리즘을 두지 않는다.

## 8. TargetResolver 규칙

대상 결정은 다음 순서를 따른다.

1. 명시적 `.sln` 또는 지원 시 `.slnx`
   - 해당 solution만 로드한다.
2. 명시적 `.csproj`
   - 해당 project와 project reference graph를 로드한다.
3. 디렉터리
   - top-level 또는 정책상 허용된 범위에서 solution을 탐색한다.
   - 정확히 하나면 solution 모드를 사용한다.
   - 여러 개면 사용자 선택을 요구하고 종료한다.
   - solution이 없으면 `.csproj`를 탐색해 프로젝트 graph를 구성한다.
   - 프로젝트도 없으면 source-only syntax 모드로 내려간다.
4. Workspace load 실패
   - 실패 프로젝트별로 syntax fallback을 수행할 수 있다.
   - 결과 전체를 `Partial`로 표시한다.
   - 자동 apply를 금지한다.

source-only 탐색에서는 최소한 `bin`, `obj`, `.git`, generated, vendor 및 설정된 제외 경로를 제거한다.

## 9. 분석 완전도와 신뢰도 모델

### 9.1 전체 분석 상태

| 상태 | 의미 | 자동수정 |
|---|---|---|
| `CompleteSemantic` | 선택 범위의 모든 프로젝트·문서가 의미 분석됨 | 제한적 허용 |
| `PartialSemantic` | 일부 프로젝트·문서·심볼이 미해석 | 금지 |
| `SyntaxOnly` | 구문 패턴만 분석 가능 | 금지 |
| `Failed` | 대상 또는 소스를 안정적으로 읽지 못함 | 금지 |

### 9.2 예외 후보 provenance

각 후보에는 다음 출처 중 하나 이상을 기록한다.

- `ExplicitThrow`: source의 명시적 throw
- `SourcePropagation`: project source method 호출 전파
- `DocumentedMetadata`: framework/package XML 문서
- `CuratedRule`: 명시적으로 관리되는 도메인 규칙
- `Unknown`: 심볼 또는 구현을 해석하지 못함

`DocumentedMetadata`는 가능성의 근거일 뿐 완전 목록으로 취급하지 않는다.

## 10. 제한적 자동수정 정책

### 10.1 기본 정책

- 기본 실행은 항상 analyze 또는 preview다.
- `CompleteSemantic` 상태가 아니면 apply를 허용하지 않는다.
- 미해석 operation, workspace error 또는 physical file 충돌이 하나라도 있으면 apply를 허용하지 않는다.
- 변경은 파일 단위가 아니라 solution change set 단위로 승인한다.
- generated 및 solution root 외부 파일은 기본 수정 금지다.

### 10.2 자동 적용 금지 항목

- catch filter의 제거 또는 변경
- 원본 catch body의 삭제 또는 `Debug.WriteLine` 대체
- 사용자 승인 없는 broad fallback 제거
- 불완전 예외 후보를 완전 목록으로 간주한 catch 분리
- baseline compilation 진단이 증가하는 변경
- 동일 physical file에 project context별로 서로 다른 수정안이 생성된 경우

### 10.3 단계별 수정 수준

| 수준 | 동작 | 소스 기록 |
|---|---|---|
| `Analyze` | 진단과 근거만 생성 | 없음 |
| `Preview` | 적용 가능한 patch/diff 생성 | 없음 |
| `ApprovedApply` | 사용자가 선택한 변경만 적용 | 있음 |
| `UnsafeOverride` | broad fallback 제거 등 의미 변경 가능 | 기본 비활성, 별도 명시 필요 |

초기 버전에서는 non-empty body 또는 filter가 있는 broad catch를 `Preview`까지만 지원한다. broad fallback을 제거해야 하는 조직 규칙은 자동 안전 변환이 아니라 명시적 정책 변경으로 취급한다.

### 10.4 자동 적용 Safety Gates

자동 apply는 다음 조건을 모두 통과해야 한다.

| Gate | 조건 |
|---|---|
| `G0 Target` | 대상 solution/project가 하나로 확정됨 |
| `G1 Coverage` | 누락 project/document가 없고 physical file 충돌이 없음 |
| `G2 Workspace` | 치명적 workspace/project evaluation 오류가 없음 |
| `G3 Analysis` | 결과가 `CompleteSemantic`이며 unresolved evidence가 없음 |
| `G4 Rewrite` | 허용된 변환이며 원본 body/filter/trivia를 임의 삭제하지 않음 |
| `G5 Validation` | 전체 change set 검증 후 신규 compiler diagnostic이 증가하지 않음 |
| `G6 Concurrency` | 분석 시점과 적용 시점의 파일 content hash가 동일함 |
| `G7 Approval` | 사용자가 preview diff를 명시적으로 승인함 |
| `G8 Persistence` | encoding을 보존한 atomic batch write와 rollback이 가능함 |
| `G9 Verification` | 설정된 build/test 명령이 통과함 |

Gate 하나라도 실패하면 디스크를 변경하지 않고 `PatchOnly` 또는 `ReportOnly`로 전환하며, 실패한 gate와 근거를 보고서에 기록한다.

## 11. 단계별 구현 계획

### Phase 0. 즉시 안전 잠금

- [ ] GUI의 직접 `apply: true` 제거
- [ ] preview와 apply 버튼 분리
- [ ] `.sln` 0개/복수 시 raw apply 금지
- [ ] generated 및 `bin/obj` 수정 금지
- [ ] catch body/filter를 버리는 기존 rewrite 비활성화

완료 조건:

- 사용자가 명시적 apply를 선택하기 전에는 소스 파일이 변경되지 않는다.
- 대상 해석이 모호하거나 partial이면 apply 진입이 불가능하다.

### Phase 1. 입력 해석 및 coverage 통합

- [ ] `.sln`, `.csproj`, directory를 처리하는 `TargetResolver` 구현
- [ ] analyze/fix/UI/CLI가 동일 resolver 사용
- [ ] project/document/source inventory 및 누락 사유 수집
- [ ] `CompleteSemantic/PartialSemantic/SyntaxOnly/Failed` 결과 도입
- [ ] structured workspace diagnostics 및 exit code 정의

완료 조건:

- 입력 종류별 동작이 결정적이며 테스트로 고정된다.
- 물리 `.cs`와 workspace document의 차이가 보고서에 나타난다.
- 누락이 있는 실행은 성공으로 표시되지 않는다.

### Phase 2. 의미 분석 엔진 재구성

- [ ] project별 semantic model resolver 구현
- [ ] ProjectReference를 건너가는 호출 지원
- [ ] `IOperation` 기반 throw-capable operation 수집
- [ ] nested try/lambda/local function 경계 처리
- [ ] cycle-safe call graph 및 method summary cache 구현
- [ ] target framework별 metadata documentation provider 구현
- [ ] exception provenance 및 unknown operation 기록

완료 조건:

- cross-project fixture가 예외 없이 분석된다.
- 직접 throw, constructor, property, nested try 및 순환 호출 테스트가 통과한다.
- 미해석 호출 수와 위치가 결과에 포함된다.

### Phase 3. 제한적 code fix 및 검증

- [ ] `DocumentEditor`/`SyntaxEditor` 기반 최소 변경
- [ ] body/filter/trivia 보존 정책 구현
- [ ] physical path deduplication 및 외부 파일 경계 검사
- [ ] 전체 solution snapshot에 변경 누적
- [ ] diagnostic multiset 비교
- [ ] encoding/BOM/line ending 보존
- [ ] atomic apply 및 실패 rollback

완료 조건:

- preview와 apply 결과가 동일하다.
- 실제 변경 수와 보고된 변경 수가 일치한다.
- 변경 전 존재하지 않던 compilation error가 추가되지 않는다.
- 원본 handler, filter, encoding 및 line ending 보존 테스트가 통과한다.

### Phase 4. 제품화 및 회귀 테스트

- [ ] Core, CLI, WPF, Tests 프로젝트 분리
- [ ] Markdown/JSON/SARIF 결과 제공
- [ ] cancellation, progress 및 UI 중복 실행 방지
- [ ] README 및 운영 문서 갱신
- [ ] fixture solution 기반 CI 구성

## 12. 필수 테스트 매트릭스

### 입력 및 Workspace

- [ ] 명시적 `.sln`
- [ ] 명시적 `.csproj`
- [ ] solution 없는 단일 project 폴더
- [ ] 여러 `.sln`이 있는 저장소
- [ ] nested solution
- [ ] restore 실패 project
- [ ] SDK/targeting pack 누락
- [ ] Debug/Release 출력이 없는 project
- [ ] multi-project ProjectReference
- [ ] linked source file
- [ ] multi-target project
- [ ] conditional compilation
- [ ] source-generated document

### 분석 정확성

- [ ] 직접 throw
- [ ] constructor/object creation
- [ ] property/indexer
- [ ] operator/conversion
- [ ] async/await
- [ ] iterator/using/Dispose
- [ ] nested try와 내부 catch
- [ ] lambda/local function
- [ ] global namespace
- [ ] partial method/type
- [ ] 순환 호출 및 5단계 초과 호출
- [ ] framework와 유사한 사용자 namespace
- [ ] NuGet XML documentation

### 수정 안전성

- [ ] catch filter 보존
- [ ] 원본 로거 및 side effect 보존
- [ ] catch 내부 주석/trivia 보존
- [ ] 부모/자식 try 동시 후보
- [ ] 동일 physical file의 다중 project context
- [ ] solution root 밖 linked file
- [ ] UTF-8 BOM, UTF-16 및 legacy encoding
- [ ] LF/CRLF 보존
- [ ] 기존 compiler error와 동일 ID의 신규 오류
- [ ] 여러 파일 중간 실패 시 rollback
- [ ] preview 시 디스크 무변경

## 13. Definition of Done

다음 조건을 모두 만족해야 "분석기 + 제한적 자동수정기" 전환이 완료된 것으로 본다.

- [ ] 대상 해석이 `.sln/.csproj/directory`에서 일관된다.
- [ ] 분석된 프로젝트·문서와 누락된 항목이 모두 보고된다.
- [ ] cross-project 호출이 올바른 semantic model로 분석된다.
- [ ] 결과에 완전도, provenance 및 unresolved 정보가 포함된다.
- [ ] partial/syntax-only 상태에서 자동수정이 차단된다.
- [ ] 원본 catch body/filter를 임의로 삭제하지 않는다.
- [ ] broad fallback 제거는 기본 자동수정에서 제외된다.
- [ ] 변경을 전체 solution snapshot에서 검증한다.
- [ ] 진단 위치·메시지·개수 증가를 검출한다.
- [ ] linked/generated/external 파일 정책이 적용된다.
- [ ] 인코딩, BOM 및 줄바꿈이 보존된다.
- [ ] preview가 기본이며 사용자 승인 후에만 apply된다.
- [ ] 필수 fixture 및 regression test가 CI에서 통과한다.
- [ ] README가 실제 기능과 제한을 정확히 설명한다.

## 14. 권장 작업 순서

1. Phase 0 안전 잠금을 최우선 적용한다.
2. `TargetResolver`와 coverage 모델을 먼저 완성한다.
3. cross-project semantic model 문제와 분석 엔진을 수정한다.
4. 분석 결과에 신뢰도와 provenance를 추가한다.
5. 그 이후에만 새로운 code fix를 구현한다.
6. 마지막으로 UI apply를 다시 활성화한다.

새로운 예외 규칙을 추가하거나 LLM 판단을 연결하는 작업은 위 기반이 완성된 이후에 진행한다. 현재 가장 큰 위험은 규칙 부족이 아니라 **불완전한 분석이 완전한 결과처럼 취급되고 바로 소스 변경으로 이어지는 구조**다.
