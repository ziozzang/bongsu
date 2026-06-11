# 네이티브 통합 수집 에이전트 설계

> 상태: 설계 + 1차 구현 진행 중. trivy 외부 의존성 제거 + 스캐너·메타정보 통합.

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

1. [완료] 호스트 facts 네이티브 수집 → `hosts.facts`
2. [완료] 멀티런타임 컨테이너 열거 (docker/podman/nerdctl/crictl)
3. [진행] dpkg/apk 네이티브 패키지 리더 (`ScanRoot(root)`)
4. facts를 root 파라미터화 → 컨테이너 rootfs에 재사용
5. 컨테이너 rootfs 경로 해석 + 컨테이너별 facts → `container_assets.facts`
6. rpm sqlite 네이티브 리더 + 바이너리 폴백
7. 에이전트 스캐너 모드 선택 (`--scanner native|trivy`), 기본 native
8. 언어 생태계 lockfile 스캐너 (npm/pypi/go/cargo/...)

## 호환성

서버측 매칭은 `pkg_type` + `ecosystem` 정규화에 의존하므로, 네이티브 스캐너는
trivyparse의 `ecosystemForType` 매핑과 **동일한 pkg_type/ecosystem 값**을 채운다
(debian/ubuntu/alpine/rhel ↔ Debian/Ubuntu/Alpine/RHEL). 이로써 trivy 출력과
네이티브 출력이 매칭 측면에서 구별되지 않는다.
