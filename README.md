# ExceptionAnalyzerLight

**Try-Catch 구문의 신뢰성 검출 자동화 도구**

---

## 📌 프로젝트 개요

`ExceptionAnalyzerLight`는 C# 프로젝트 내에서 **모든 메서드 호출 경로를 분석하여**,  
각 메서드에서 발생 가능한 **세분화된 예외(Exception)** 목록을 추론하는 도구입니다.

이 도구는 **신뢰성 시험(Reliability Test)** 항목 중  
`catch(Exception)` 또는 광범위한 예외 처리 방식이  
**구체적 예외 식별을 어렵게 만들 수 있는 문제**를 해결하기 위해 제작되었습니다.

즉, **전역적 예외 처리 방식**이 아닌,  
**정확하고 구체적인 예외 처리(catch 구문 분리)**가 이루어졌는지를 자동 검출합니다.

---

## 🎯 핵심 목적

- ✅ **신뢰성 시험 기준 만족**
  - 전역 Exception 사용(catch(Exception))이 아닌,  
    발생 가능한 세부 예외별로 `catch` 블록이 정의되어야 함을 검증

- ✅ **정적 분석 기반 자동화**
  - 복잡한 호출 관계에서도 발생 가능한 예외를 자동 추론

- ✅ **예외 설명 제공**
  - 예외 이름만 나오는 로그가 아닌, 개발자 이해를 돕기 위한 한국어 설명 자동 제공

---

## ⚙ 주요 기능

- 🔍 **재귀적 호출 분석**: 프로젝트 내부 메서드는 물론, .NET API 호출까지 재귀적으로 추적
- 📊 **예외 추론 자동화**: ExceptionMap을 기반으로 메서드별 예외를 매핑하여 정리
- 🧠 **예외 설명 주석화**: ExceptionDescriptionMap을 기반으로 한국어 예외 설명 자동 생성
- 📄 **분석 결과 출력**: 호출 API 및 발생 가능한 예외를 파일로 자동 정리 (`*_ApiCallCandidates.txt`)

---

## 💬 예외 추론 예시

```csharp
ExceptionMap.Add("System.IO.File.Delete", new[] { "IOException", "UnauthorizedAccessException", "ArgumentException" });

ExceptionDescriptionMap.Add("IOException", "I/O 오류가 발생했을 때 발생합니다.");
ExceptionDescriptionMap.Add("UnauthorizedAccessException", "파일에 대한 권한이 없을 경우 발생합니다.");
ExceptionDescriptionMap.Add("ArgumentException", "잘못된 인수가 전달되었을 때 발생합니다.");

📁 출력 예시
 🔧 System.Security.Principal.WindowsIdentity.GetCurrent()
        → 예상 예외: SecurityExceptionSecurityException - 보안 제약 조건을 위반했을 때 발생합니다.
    🔧 System.Enum.HasFlag()
        → 예상 예외: ArgumentExceptionArgumentException - 인수에 잘못된 값이 전달되었을 때 발생합니다.



📍 활용 시나리오
✅ 개발자 코드 리뷰 시 광범위한 catch(Exception) 사용 여부 검출

✅ 예외 상황에 대한 단위 테스트 시 시나리오 분기 설계 근거 제공

✅ 통합 테스트/QA 단계에서 예외 처리가 구체적으로 정의되었는지 검증

📦 기술 스택
.NET 6.0
Roslyn 코드 분석 API
System.Reflection
정적 문법 트리(SyntaxTree)

📌 향후 계획
 API LLM 학습
 대상 프로젝트 자동 환경설정

