# ExceptionAnalyzer

**C# `try-catch` 명시적 예외선언 자동화 도구** — 과광역 `catch (Exception)`을 정적 분석으로 추론한 **구체 예외 catch 목록(파생→기반 정렬, 컴파일 보증)** 으로 소스에서 직접 교체합니다.

신뢰성 시험에서 "전역 `catch(Exception)` 금지, 발생 가능한 세부 예외별 catch 분리" 요구를 만족시키기 위한 도구입니다. Roslyn 기반이며, .NET Framework 구형 프로젝트(non-SDK csproj)와 SDK 스타일 프로젝트를 모두 지원합니다.

## 무엇을 하는가 (BEFORE → AFTER)

```csharp
// BEFORE — 과광역 catch
try { int n = int.Parse(s); var sw = new StreamWriter(path); }
catch (Exception ex) { Log(ex); }

// AFTER — 도구가 소스를 직접 재작성 (파생→기반 순서, 셀프 컴파일 검증 통과)
try { int n = int.Parse(s); var sw = new StreamWriter(path); }
catch (System.ArgumentNullException ex) { Log(ex); }
catch (System.IO.DirectoryNotFoundException ex) { Log(ex); }
catch (System.IO.PathTooLongException ex) { Log(ex); }
catch (System.OverflowException ex) { Log(ex); }
catch (System.ArgumentException ex) { Log(ex); }
catch (System.FormatException ex) { Log(ex); }
catch (System.IO.IOException ex) { Log(ex); }
catch (Exception ex) { Log(ex); } // 원본 broad fallback 보존
// ... (해당 try에서 실제 추론된 예외만 생성됨)
```

- 예외 근거는 .NET **XML 문서**(`<exception>` 태그)와 **심볼 문서**에서 나옵니다(추측 아님).
- 새 `System.Exception` catch-all은 만들지 않습니다. 다만 원래 있던 broad catch는 fallback으로 보존합니다.
- 기존 catch 본문이 단일 호출문이면 원래 `Exception` 정적 타입 alias를 만든 뒤 그 호출을 각 구체 catch에 복제합니다. 원본 broad catch는 fallback으로 남겨 미추론 예외의 런타임 동작을 보존합니다.

## 요구사항

| 항목 | 필수 여부 |
|---|---|
| Windows + **.NET 9 Desktop Runtime** | 필수 (앱 실행) |
| **.NET SDK 9+** 또는 Visual Studio 2022 | 솔루션(.sln) 모드에 필요 (MSBuildWorkspace 프로젝트 로드) |
| `.NET Framework 4.7.2 Reference Assemblies`의 `ko\*.xml` | 선택 — 있으면 **한글 예외 설명** 제공, 없으면 심볼 문서로 자동 저하 |
| 대상 프로젝트 빌드 여부 | 솔루션 모드는 **미빌드 상태도 로드 가능**. 폴더 모드는 `bin\Debug` DLL이 있으면 정확도↑ |

## 빠른 시작

### GUI (권장)
1. `ExceptionAnalyzer.exe` 실행
2. 경로 입력란에 **`.sln` 파일 경로**를 넣거나 [폴더 선택]으로 지정 (폴더는 최상위에 `.sln`이 정확히 1개일 때만 허용)
3. **[분석 + 소스 자동수정]** 클릭
4. 로그창에 **미리보기(BEFORE/AFTER)** 가 표시되고, 확인창에 `수정 예정 N건 / 수동 검토 M건 / 완전도` 요약이 뜸 — 이 시점까지 **파일은 변경되지 않음**
5. [예] → 실제 적용. [아니요] → 미리보기만 하고 종료
6. [결과 폴더 열기] → `fix-report.txt` 등 산출물 확인

> ⚠️ 적용은 소스 파일을 직접 덮어씁니다. **git 등 버전관리 하에서 실행하세요.**

### CLI

```
ExceptionAnalyzer.exe --analyze <.sln|폴더>            # 분석만 (catch 권장 목록 텍스트 산출)
ExceptionAnalyzer.exe --fix <.sln|폴더>                # 수정 미리보기 (파일 무변경, fix-report.txt 생성)
ExceptionAnalyzer.exe --fix <.sln|폴더> --apply        # 실제 소스 수정
ExceptionAnalyzer.exe --fix <폴더> --source-only          # .sln 없는 폴더를 파일 스캔으로 진단(PARTIAL, CLI apply 차단)
ExceptionAnalyzer.exe --selftest | --selftest-xml | --selftest-fix   # 자가 검증 (headless)
```

| Exit code | 의미 |
|---|---|
| `0` | 성공, 완전한 결과 (Completeness=Complete). 커버리지 참고(비차단)는 있을 수 있음 |
| `1` | 치명 오류(`.sln` 0개/복수인 폴더를 `--source-only` 없이 지정 등) **또는 저장 실패**(`ApplyFailed` — 쓰기 예외/외부 수정 감지로 롤백) |
| `2` | **부분 결과(무결성 문제)** — 워크스페이스 로드 실패·baseline 컴파일 오류·문서 스킵·source-only 정책. `--apply`는 수행하지 않음. fix-report의 `INTEGRITY FAILURES` 확인. **커버리지 부족은 여기에 해당하지 않음(비차단)** |

**산출물** (exe 실행 폴더에 생성):
- `fix-report.txt` — MODE(PREVIEW/APPLY), 수정/스킵 카운트, `Completeness`, `ApplyFailed`/`AppliedFiles`, `INTEGRITY FAILURES`(차단)·`COVERAGE NOTES`(비차단) 섹션, 전체 BEFORE/AFTER, 수동 검토 목록
- `<대상>_ApiCallCandidates.txt` — try별 호출 API + 예상 예외 + catch 권장 순서 + 붙여넣기용 스켈레톤
- `<대상>_UnregisteredExceptionMap.txt` — 예외 정보를 찾지 못한 항목
- `selftest*-result.txt` — 자가 검증 상세

## 동작 원리 (파이프라인)

1. **대상 해석** — `.sln` 파일 또는 단일 `.sln` 폴더 → `MSBuildWorkspace`로 전 프로젝트 로드(구형 net472 csproj 포함, 미빌드 가능). `.sln` 0/복수 폴더는 명시적 실패(조용한 확대 금지; `--source-only`는 PARTIAL 진단용 파일 스캔만 허용).
2. **try 수집** — 프로젝트별 컴파일에서 모든 `TryStatementSyntax`.
3. **예외 유발 노드 수집** (`CollectThrowCapable`) — 메서드 호출 + **생성자(new)** + **직접 throw(문/식)** + property/indexer 접근. **실행 경계 준수**: 람다/로컬함수 본문(정의≠실행)과 중첩 try의 보호 블록(내부 catch가 처리)은 제외하되 중첩 try의 catch/finally 본문은 포함. 사용자 메서드는 같은 컴파일 내에서 재귀 추적(최대 깊이 5).
4. **예외 문서 조회** (`LookupDocumentedExceptions`) — 1차: v4.7.2 `ko` XML 캐시(한글 설명), 미스 시 심볼의 실제 참조 문서(`GetDocumentationCommentXml`, 대상 TFM/NuGet 반영).
5. **catch 목록 확정** — `System.Exception` 제거 → 상속 깊이 정렬(파생→기반, CS0160 원천 차단) → 미해석 타입 격리 → **합성 catch를 실제 컴파일해 CS0160/CS0161 부재 보증**.
6. **재작성** — 구체 catch를 원본 broad catch 앞에 삽입하고 broad fallback은 보존(원본 try 본문·finally·트리비아 보존), 변경 노드만 포맷(파일 전체 재포맷 없음), **원본 인코딩(BOM/UTF-16/CP949)·개행(CRLF/LF) 보존**.
7. **적용 후 검증** — 파일 재컴파일 후 **Id+메시지 지문 비교**로 신규 오류 검출 시 해당 파일 전체 롤백(`CompileReverted`).
8. **저장** — 전 파일 검증 통과 후 **일괄** 쓰기(atomic: 같은 볼륨 임시파일→`File.Replace`). 쓰기 직전 **스캔 시점 원본 바이트와 디스크 재대조**(외부 수정 감지 시 배치 전체 중단, `ApplyFailed`).

### 무결성 게이트 vs 커버리지 참고 (중요)

apply 차단 여부는 **무결성(integrity)** 위협에서만 결정됩니다:

| 분류 | 예 | apply 영향 |
|---|---|---|
| **무결성 실패(차단)** `INTEGRITY FAILURES` | 워크스페이스/프로젝트 로드 실패, baseline 컴파일 오류, 문서 스킵, `--source-only` 정책 | **PARTIAL → apply 차단(exit 2)** |
| **커버리지 참고(비차단)** `COVERAGE NOTES` | 문서 없는 API·생성자·속성, `await`/`foreach`/`using`/LINQ, 외부 라이브러리 호출, 심볼 해석 실패, 링크 파일 | **차단 안 함** — 원본 broad catch가 fallback으로 남아 미추론 예외를 그대로 잡으므로 런타임 안전. "구체 catch 목록이 완전하지 않을 수 있음"의 정보성 표기일 뿐 |

## 안전 규칙 (무엇을 고치고, 무엇을 건드리지 않는가)

**수정 대상이 되려면 전부 만족해야 함:**
- catch가 **정확히 1개**이고 (`finally`는 허용·보존)
- 그 catch가 **과광역**: `catch { }` 또는 `catch (Exception)` / `catch (System.Exception)`
- 본문이 **교체 안전**: 비어있거나, 호출문 1줄 (`Log(ex);` 등). `catch when` 필터는 보존 의미가 달라질 수 있어 수동 검토로 넘김
- 추론된 구체 예외가 **1개 이상** (0개면 catch 없는 try를 만들지 않고 스킵)

**절대 건드리지 않는 것** (스킵 + 리포트에 사유 기록):
- 본문에 `throw`/`return`/선언/여러 문장이 있는 catch → **수동 검토 목록**
- 이미 구체 타입인 catch, 다중 catch
- `obj\`·`bin\`·`.git\` 하위, `*.g.cs`·`*.Designer.cs`·`*.generated.cs` 등 생성 파일
- 링크 공유 파일의 중복 프로젝트 컨텍스트(최초 1회만 수정)

**보장 성질:**
- **미리보기 무변경** — `--apply` 없으면 디스크에 손대지 않음
- **멱등** — 같은 입력에 재실행해도 추가 변경 0 (이미 고친 곳은 구체 catch라 대상에서 자연 제외)
- **인코딩·개행·기존 포맷 보존** — CP949 한글 소스 포함
- **동작 보존** — 원본 broad catch를 fallback으로 남기고, 기존 catch 본문(단일 호출)을 원본 예외 타입 alias로 각 구체 catch에 복제 → 관측 런타임 동작 불변
- **저장 안전** — atomic write + 전 파일 검증 후 일괄 쓰기 + 적용 직전 외부 수정 감지. 저장 실패 시 `ApplyFailed`(exit 1)로 보고
- Completeness=**PARTIAL**(exit 2)은 **무결성 문제**(워크스페이스/baseline/문서 스킵/source-only)일 때만이며 그때 자동수정이 차단됨. `INTEGRITY FAILURES`에 사유 기록. **커버리지 참고(비차단)는 apply를 막지 않음**

## [AUTO-CATCH] 로거 치환 파이프라인 (운영 절차)

이 도구는 catch **구조**(타입·순서·컴파일 보증)를 결정론적으로 만들고, 기존 단일 호출 로거와 원본 broad fallback은 보존합니다. 원래 빈 catch였던 곳만 후속 치환 대상입니다:

1. 도구 적용 → 기존 단일 호출 catch는 그대로 복제되고, 빈 catch에서 생성된 구체 catch만 `[AUTO-CATCH] 원본 빈 catch` 주석으로 표시됨
2. `[AUTO-CATCH]` 마커를 grep → 사내 LLM(또는 스크립트)에 "이 프로젝트의 로깅 규약(`LogUtil.Error(ex)` 등)으로 치환" 반복 작업 지시
3. 빈 catch에서 생성된 구체 catch는 동작 변경 없이 주석 마커만 가지므로, 프로젝트 로거 규약에 맞춰 후속 치환 가능

## 알려진 한계 (정직)

| 한계 | 동작 | 후속 계획 |
|---|---|---|
| **프로젝트 간(ProjectReference) 호출의 예외 추론 불가** | 크래시 없이 안전 생략, 해당 try는 "추론 없음"으로 리포트 | Epic [#1](../../issues/1) Workstream 3 |
| XML 문서 자체의 불완전성 | 문서에 없는 예외는 추론 불가(전파됨 — fail-fast 의도) | 큐레이션 오버레이 후보 |
| 외부 라이브러리(DevExpress/Arction/사내 DLL 등) 예외 | XML 문서 없으면 추론 불가 | 동상 |
| 연산자/변환(checked 오버플로 등) 미수집 | 범위 외 | WS3 |
| 비자명 catch 본문 | 설계상 수동 검토(원본 로직 보존 우선) | 본문 보존 모드 옵션 후보 |
| **무결성 문제 시 솔루션 전체 apply 차단(all-or-nothing)** | 파일 하나라도 baseline 컴파일 오류/로드 실패면 전 솔루션 apply 차단 | 파일럿에서 수율 저하 확인 시 파일 단위 게이트로 재조정 |
| apply 1회에 전체 스캔 3회(호출측+내부 프리뷰+본실행) | 대형 솔루션에서 벽시계 비용 | 스캔 통합 최적화(후속) |

## 코드 맵 (개발자·에이전트용)

단일 WPF 프로젝트 + 테스트. `Program`은 전역 네임스페이스의 `internal partial class`(all-static)로 5개 파일에 분할:

| 파일 | 책임 | 핵심 멤버 |
|---|---|---|
| `ExceptionAnalyzer/Program.cs` | 대상 해석·워크스페이스·IO 유틸 | `ResolveSolutionPath`, `TryResolveSingleSolutionPath`, `OpenSolutionWorkspace`, `ReadSourcePreserving`(인코딩/EOL 감지), `IsExcludedSourcePath` |
| `Program.Docs.cs` | 예외 문서 | `LoadXmlDocumentation`(ko 캐시), `LookupDocumentedExceptions`(캐시→심볼 fallback) |
| `Program.Analysis.cs` | 분석 엔진 | `AnalyzeDirectory`(--analyze), `AnalyzeTryBlock`, `AnalyzeInternalMethod`(재귀), `CollectThrowCapable`(수집+실행경계), `GetOrderedResolvedCatchTypes`(필터+정렬), `ValidateCatchOrder`(셀프컴파일), `BuildReferences` |
| `Program.Fix.cs` | 소스 재작성 | `FixResult`(무결성/커버리지/ApplyFailed 분리), `RunFix`(진입), `RunFixSolution`, `ProcessFixRoot`(적격판정→교체→검증→저장), `CollectCoverageWarnings`, `IsOverBroadCatch`, `IsReplaceSafeBody`, `BuildReplacementTry`, `DiffIntroducedErrors`(진단 지문), `ApplyPendingWrites`(atomic 일괄+TOCTOU 가드), `WriteFixReport` |
| `Program.SelfTest.cs` | 자가 검증 | `RunSelfTestHeadless`, `RunSelfTestFix`([1]~[24] 픽스처 하니스) |
| `App.xaml.cs` | CLI 디스패치(모드·exit code) | `--selftest*` / `--fix` / `--analyze` 분기 |
| `MainWindow.xaml(.cs)` | GUI (미리보기→확인→적용) | `Analyze_Click` |
| `tests/ExceptionAnalyzer.Tests` | xunit 9 facts (셀프테스트 3종 + 지문·분류·TOCTOU 단위검증) | `dotnet test` |

### 확장 포인트 (응용 작업 시 어디를 고치나)

- **수집 노드 추가**(예: 연산자) → `CollectThrowCapable` + `Program.Analysis.cs`의 대응 처리 헬퍼
- **수정 대상 정책 변경**(예: 본문 보존 모드) → `IsReplaceSafeBody`(적격판정) + `BuildReplacementTry`(본문 생성)
- **placeholder 문구 변경** → `BuildReplacementTry`의 catch 생성 문자열 1곳
- **예외 문서 소스 추가**(큐레이션 오버레이 등) → `LookupDocumentedExceptions`
- **새 CLI 모드** → `App.xaml.cs` OnStartup 분기 + `Program.SelfTest.cs`에 대응 셀프테스트 추가 권장
- **검증 강화** → `DiffIntroducedErrors`(지문) / `ProcessFixRoot`(롤백 지점)

### 검증 방법 (수정 후 반드시)

```
dotnet build ExceptionAnalyzer.sln                                   # 0 오류
dotnet run --project ExceptionAnalyzer/ExceptionAnalyzer.csproj -- --selftest       # 정렬·필터·셀프컴파일
dotnet run --project ExceptionAnalyzer/ExceptionAnalyzer.csproj -- --selftest-xml   # XML 조회 경로
dotnet run --project ExceptionAnalyzer/ExceptionAnalyzer.csproj -- --selftest-fix   # 재작성 [1]~[24]
dotnet test tests/ExceptionAnalyzer.Tests/ExceptionAnalyzer.Tests.csproj
```
전부 exit 0 이어야 합니다. 재작성 로직을 바꿨다면 `--fix <픽스처>`(프리뷰)로 BEFORE/AFTER를 눈으로 확인한 뒤 `--apply` 케이스를 `RunSelfTestFix`에 추가하세요.

## 로드맵

재설계 Epic과 검증 감사 이력은 [이슈 #1](../../issues/1)에 있습니다 — P0/P1/P2 16건 검증(15 CONFIRMED), 상위 13건 수정 완료, 잔여는 Workstream 3(크로스 프로젝트 추론)·5(솔루션 스냅샷 검증)·6(atomic write)·7(프로젝트 분리).
