# 네이티브 통합 수집 에이전트 설계

> 상태: 출하됨. 네이티브 스캐너가 에이전트 기본값(trivy 외부 의존성 제거), 호스트·컨테이너 facts 수집, 언어 라이브러리/런타임 탐지까지 구현 완료. 아래 "단계"의 대부분이 완료 상태다.

## 핵심 원칙

**수집 대상(target)마다 `{패키지, facts}`를 함께, 외부 바이너리 없이 수집한다.**

대상은 두 종류:
1. **호스트** — 루트 `/` (또는 `--scan-root`)
2. **컨테이너** — 컨테이너의 rootfs (실행 중인 각 컨테이너)

스캐너와 메타정보는 분리된 기능이 아니라, **한 대상에 대한 한 번의 수집**의 두 산출물이다.

```
CollectTarget(root) → {
    facts:    CollectFacts(root)      // os-release, kernel, cpu, dmi, ...
    packages: ScanRoot(root)         // dpkg / apk / rpm DB 직접 파싱
}
```

호스트면 `root = /`, 컨테이너면 `root = <컨테이너 rootfs>`. 같은 코드가 양쪽에 동작한다.

## 왜 네이티브인가

trivy는 ~100MB 정적 바이너리 + 자체 DB 업데이트 + 컨테이너당 서브프로세스 비용이
든다. 봉수는 이미 서버측 CVE 매칭(`cve_affected_packages`)을 갖고 있으므로, 에이전트는
**설치된 패키지 목록만 정확히** 뽑으면 된다. 그건 패키지 DB 파일을 읽는 일이고,
순수 Go로 충분하다.

| 대상 | 소스 파일 | 파서 |
|---|---|---|
| Debian/Ubuntu | `var/lib/dpkg/status` | `scanner/dpkg.go` (RFC822 stanza) |
| Alpine | `lib/apk/db/installed` | `scanner/apk.go` (P:/V:/A:/o: stanza) |
| RHEL/RPM | `var/lib/rpm/rpmdb.sqlite` 또는 BDB/NDB | `scanner/rpm.go` (sqlite 우선, 복잡 포맷은 `rpm` 바이너리 폴백) |
| 언어 라이브러리 | lockfile/manifest | `scanner/lang_*.go` (향후) |

rpm DB는 포맷이 3종(BerkeleyDB Hash / NDB / sqlite)이라 sqlite를 우선 네이티브로
읽고, 구형 BDB는 `rpm` 바이너리가 있으면 폴백한다. dpkg/apk(데비안·우분투·알파인)는
완전 네이티브로 trivy 없이 동작 — 현재 대다수 컨테이너 베이스가 여기 해당.

## 컨테이너 rootfs 접근

trivy의 `image` 스캔 대신, 실행 중인 컨테이너의 **머지된 rootfs**를 호스트에서 직접
읽는다. 런타임 CLI(컨테이너 열거에 이미 사용 중)로 마운트 경로를 얻는다:

| 런타임 | rootfs 경로 획득 |
|---|---|
| docker/podman/nerdctl | `inspect` → `GraphDriver.Data.MergedDir` (overlayfs merged) |
| 폴백 | `<runtime> exec <id> cat <db-path>` — 런타임 CLI 경유 (trivy 불필요) |

머지 경로를 얻으면 `ScanRoot(mergedDir)` + `CollectFacts(mergedDir)`가 그대로 컨테이너
내부 패키지와 컨테이너 자신의 os-release/메타를 수집한다. 런타임 CLI는 컨테이너를
세는 데 이미 필요하므로 새 의존성이 아니다.

## 저장 모델

- **호스트 facts**: `hosts.facts` JSONB (구현 완료, 검증됨)
- **컨테이너 facts**: `container_assets.facts` JSONB (추가 예정) — 컨테이너별
  os-release/패키지매니저 종류/배포판 버전
- **패키지**: 기존 `packages` 테이블 (asset_type=host|container, container_id로 구분)

## 단계

1. [완료] 호스트 facts 네이티브 수집 → `hosts.facts` (migration 055)
2. [완료] 멀티런타임 컨테이너 열거 (docker/podman/nerdctl/crictl)
3. [완료] dpkg/apk 네이티브 패키지 리더 (`ScanRoot(root)`)
4. [완료] facts를 root 파라미터화 → 컨테이너 rootfs에 재사용
5. [완료] 컨테이너 rootfs 경로 해석 + 컨테이너별 facts → `container_assets.facts` (migration 056)
6. [완료] rpm 네이티브 리더(sqlite) + `rpm` 바이너리 폴백(호스트/컨테이너 `<runtime> exec`)
7. [완료] 에이전트 스캐너 모드 선택 (`-scanner native|trivy`, `BONGSU_AGENT_SCANNER`), 기본 native
8. [완료] 언어 LIBRARY 스캐너 (`ScanLanguagePackages`) + 언어 RUNTIME 탐지 (`ScanRuntimes`, CPE-product)

## 호환성

서버측 매칭은 `pkg_type` + `ecosystem` 정규화에 의존하므로, 네이티브 스캐너는
trivyparse의 `ecosystemForType` 매핑과 **동일한 pkg_type/ecosystem 값**을 채운다
(debian/ubuntu/alpine/rhel ↔ Debian/Ubuntu/Alpine/RHEL). 이로써 trivy 출력과
네이티브 출력이 매칭 측면에서 구별되지 않는다.

---

## Runtime detection (shipped) — `internal/agent/scanner/runtime.go`

OS package DB 스캔(`ScanRoot`)과 언어 LIBRARY 스캔(`ScanLanguagePackages`,
lockfile/dist-info만 읽음)은 **언어 런타임 인터프리터/VM 자체**를 놓친다. pyenv로
컴파일한 CPython, `/opt`에 풀어둔 Node tarball, 수동 설치한 JDK, Go SDK 트리 등은
자체 CVE(CPython, Node, JVM)를 갖지만 두 패스 어디에도 안 잡힌다. `ScanRuntimes`가
이 공백을 메운다.

### Filesystem-only 원칙

런타임 탐지는 **파일시스템만** 본다 — 절대 바이너리를 실행하지 않는다
(`python --version`은 호스트 스캔에서 위험하고 느리다). 대신 각 배포 형태의 잘
알려진 on-disk 레이아웃에서 버전을 추론하고, 구체적인 `X.Y` 또는 `X.Y.Z`를 얻을 수
있을 때만 패키지를 emit한다(버전 없으면 skip → 노이즈 방지). `ScanLanguagePackages`와
동일한 bounded `WalkDir` + `skipDir`/depth 가지치기를 재사용하므로 두 패스가 같은
트리를 prune한다.

트리거는 항상 `bin/` 안의 launcher 바이너리(또는 Go SDK의 `VERSION` 파일)다.
launcher 경로에 앵커링하면 `FilePath`가 실제 인터프리터를 가리켜 CPE 매칭에 적합하다.

| 런타임 | 탐지 신호 (on-disk) |
|---|---|
| CPython | `.../versions/<X.Y.Z>/bin/python*` (pyenv/python-build), `lib/python<X.Y>/` 형제 디렉터리(minor), 또는 `python_version`/`version` 파일 |
| Node.js | 경로 내 `node-vX.Y.Z` 컴포넌트(공식 tarball), 인접 `node_version`/`VERSION` 파일, 또는 번들된 npm 존재 + tarball 이름 |
| JDK/JRE | 설치 prefix의 `release` 파일(`JAVA_VERSION`/`IMPLEMENTOR` key=value); implementor로 vendor 구분 |
| Go SDK | `<goroot>/VERSION` 첫 줄(`go1.22.1`), 토큰 그대로 보존 |
| Ruby | `lib/ruby/<X.Y.Z>/` (rbenv/ruby-build/소스 설치 공통 레이아웃) |
| PHP | 인접 `php_version`/`VERSION` 파일(보수적) |

### CPE-product ecosystem 값

런타임 패키지는 `PkgType="runtime"`, 그리고 `Ecosystem`에 **CPE PRODUCT 이름**
(`python` / `nodejs` / `jdk` / `golang` / `ruby` / `php`)을 채운다 — SBOM ecosystem
(PyPI / npm / Maven)이 **아니다**. 런타임 CVE는 NVD CPE product
(`cpe:2.3:a:python:python`, `:nodejs:node.js`, `:oracle:jdk` /
`:eclipse:temurin`)에 매칭되지, 라이브러리 레지스트리 ecosystem에 매칭되지 않기
때문이다. JDK는 `release`의 `IMPLEMENTOR`로 product를 고른다: Oracle → `jdk`,
Adoptium/Temurin/Eclipse → `openjdk`, 기타 → `openjdk`.

이 값은 서버의 `RematchCPE`/`compatibleCPECandidate`가 그대로 소비한다. `pkg_type`이
`runtime`으로 구별되므로 라이브러리 매처(OSV name+ecosystem)에는 절대 들어가지
않고, CPE 매처만 version-range gate로 처리한다. 매칭 규칙 전문은
[vulnerability-matching-rules.md](vulnerability-matching-rules.md) 참조.

심볼릭 링크된 launcher(python → python3 → python3.12가 한 bin/에)는
`dedupeRuntimes`가 `(name, version, path)` 기준으로 접는다.

---

## Facts collection (shipped) — 요약

facts와 패키지는 한 대상에 대한 한 번의 수집의 두 산출물이라는 원칙이 출하되었다:

- **호스트 facts** → `hosts.facts` JSONB (migration `055_host_facts.sql`),
  `hosts.facts_collected_at` 타임스탬프. `GET /api/hosts/{id}`가 `facts`로 반환하고
  대시보드의 "System Facts" 카드에 표시한다.
- **컨테이너 facts** → `container_assets.facts` JSONB
  (migration `056_container_facts.sql`), 컨테이너 행 확장에 표시.

수집 항목: os-release, kernel, cpu, memory, dmi, virtualization, network,
filesystems. `/proc`, `/sys`, `/etc`에서 순수 Go로 읽으며 별도 튜닝이 필요 없다.
컨테이너는 머지된 rootfs(`GraphDriver.Data.MergedDir`)를 root 파라미터로 같은 코드를
재사용한다.
