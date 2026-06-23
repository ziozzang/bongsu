<!-- Trinity (jikji) UI/UX design panel: codex, glm-coding, kimi, deepseek-pro, claude-opus | verifier: deepseek-v4-pro:cloud — ACCEPTed round 1. The final synthesis step hit a Trinity runtime lease timeout (opus, large spec), so this spec was synthesized locally from the verifier-accepted, strongly-convergent round-1 proposals + the current-state map, following the panel's agreed direction. -->

# Bongsu 대시보드 UI 재설계 — 디자인 명세

## 1. 디자인 원칙·방향
밀도 높은 보안 운영 콘솔(SOC)의 성격을 유지하되, **3계층 토큰 디자인 시스템 + 재사용 컴포넌트 라이브러리 + 명시적 IA**로 일관성·확장성·접근성을 끌어올린다. 다크 우선, 라이트 모드는 토큰 매핑으로 확보. 심각도는 **색 + 아이콘/형태**로 이중 인코딩(WCAG, 색맹 안전). 모놀리식 `App.tsx`(423KB)를 뷰·컴포넌트·토큰으로 분해.

## 2. 디자인 토큰 (3계층: primitive → semantic → component)
기존 hex 값을 **보존**하고 이름을 체계화한다. `web/src/styles/tokens.css`로 분리.

### 2.1 Primitive (원시값 — 모드 무관)
```css
:root {
  /* 스페이싱 (4px 기준) */
  --space-0:0; --space-1:4px; --space-2:8px; --space-3:12px; --space-4:16px;
  --space-5:20px; --space-6:24px; --space-8:32px; --space-10:40px; --space-12:48px; --space-16:64px;
  /* 타입 스케일 (1.125 비율, rem) */
  --font-2xs:0.625rem; --font-xs:0.6875rem; --font-sm:0.8125rem; --font-base:0.875rem;
  --font-md:1rem; --font-lg:1.125rem; --font-xl:1.375rem; --font-2xl:1.75rem; --font-3xl:2.25rem;
  --leading-tight:1.25; --leading-normal:1.5;
  --weight-normal:400; --weight-medium:500; --weight-semibold:600; --weight-bold:700;
  /* 반경·모션·그림자 */
  --radius-sm:6px; --radius:10px; --radius-lg:14px; --radius-full:999px;
  --transition:0.15s ease; --transition-slow:0.25s ease;
  --shadow:0 2px 12px rgba(0,0,0,.3); --shadow-lg:0 8px 32px rgba(0,0,0,.4);
  --font-sans:-apple-system,BlinkMacSystemFont,'Segoe UI','Inter','Apple SD Gothic Neo','Noto Sans KR',Roboto,sans-serif;
  --font-mono:'SF Mono','JetBrains Mono','Fira Code',Consolas,monospace;
  /* 심각도 hue (색+아이콘 이중 인코딩의 색 축) */
  --critical:#f04444; --high:#f07830; --medium:#e0b020; --low:#30c060; --unknown:#6870a0; --info:#4aa3f0;
}
```

### 2.2 Semantic (모드별 매핑 — `[data-theme]`)
```css
:root, [data-theme="dark"] {
  --bg-base:#0b0d13; --bg-raised:#10131b; --surface:#151822; --surface-hover:#1a1e2c; --surface-active:#202536;
  --overlay:#171b26;                 /* 모달/드롭다운 */
  --border-subtle:#1a1e2c; --border:#232838; --border-light:#2c3248; --border-strong:#3e4664;
  --border-focus:var(--primary);
  --text:#e8eaf0; --text-secondary:#b0b6c8; --text-muted:#6b7394; --text-placeholder:#555c78; --text-inverse:#0b0d13;
  --primary:#7c6cf0; --primary-hover:#9489f0; --primary-dim:rgba(124,108,240,.12); --primary-glow:rgba(124,108,240,.25);
  /* 심각도 배경(dim) */
  --critical-dim:rgba(240,68,68,.14); --high-dim:rgba(240,120,48,.14); --medium-dim:rgba(224,176,32,.14);
  --low-dim:rgba(48,192,96,.14); --unknown-dim:rgba(104,112,160,.14);
}
[data-theme="light"] {
  --bg-base:#f6f7fb; --bg-raised:#ffffff; --surface:#ffffff; --surface-hover:#f0f2f8; --surface-active:#e7eaf4;
  --overlay:#ffffff; --border-subtle:#eceef5; --border:#dfe3ee; --border-light:#cdd3e4; --border-strong:#aab2cc;
  --text:#1a1d28; --text-secondary:#444b60; --text-muted:#6b7394; --text-placeholder:#9aa0b4; --text-inverse:#ffffff;
  --primary:#5b4cd6; --primary-hover:#4a3cc0; --primary-dim:rgba(91,76,214,.10); --primary-glow:rgba(91,76,214,.18);
  --critical-dim:rgba(240,68,68,.10); --high-dim:rgba(240,120,48,.10); --medium-dim:rgba(224,176,32,.12);
  --low-dim:rgba(48,160,80,.12); --unknown-dim:rgba(104,112,160,.10);
}
```
- 토글: `<html data-theme>` 속성 + localStorage. 기본 dark. 시스템 선호 `prefers-color-scheme` 1회 시드.

### 2.3 심각도 이중 인코딩
컴포넌트 `<Severity level>` = dim 배경 pill + 색 텍스트 + **레벨별 아이콘**(critical=채워진 삼각경고, high=경고, medium=다이아, low=점, unknown=물음표). 색만으로 구분 금지.

## 3. 정보구조(IA)·내비게이션
- **사이드바 그룹 재편**(우선순위순): **Overview**(Dashboard, Trends, Reports) · **Security**(Vulnerabilities, CVE Search, AI Triage, Scans) · **Inventory**(Hosts, Packages, Containers, Asset Groups, Topology) · **Administration**(Users, Tokens, RBAC, Audit, AI Approvals, Schedules, Notifications). Administration은 접이식(기본 접힘).
- **URL 라우팅 도입**: `react-router-dom`(경량) 또는 자체 hash 라우터. 경로 `/dashboard`, `/vulns`, `/vulns/:id`, `/hosts/:id` 등 → 딥링크·뒤로가기·새로고침 보존(현행 `useState<View>`의 최대 약점 해소).
- **커맨드 팔레트**(⌘K/Ctrl-K): 뷰 점프 + 호스트/CVE 검색 + 액션(스캔요청, 토큰생성). 자체 구현(의존성 회피), `web/src/components/CommandPalette.tsx`.
- 사이드바: 240px 고정 + 접기 토글(64px 아이콘레일). 활성표시 유지(좌측 3px primary + dim).

## 4. 컴포넌트 시스템 (`web/src/components/`)
재사용 컴포넌트로 추출, props API 표준화:
- `Button({variant:'primary'|'secondary'|'danger'|'ghost', size:'sm'|'md', icon?, loading?})`
- `Badge`/`Severity({level, count?, showIcon?})`
- `Card({title?, actions?, padding?})` + `Card.Header/Body`
- `DataTable<T>({columns, rows, sort, onSort, loading, empty, rowKey, onRowClick, stickyHeader, virtualized?})` — 정렬/빈/로딩/sticky 헤더 내장, 수만 행은 가상 스크롤.
- `FilterBar({children, onApply, onReset})` + `Select/TextInput/Checkbox`
- `Modal({open, onClose, title, size})` (Esc/백드롭/포커스 트랩)
- `Pagination`, `RangeSwitcher`, `Tabs`, `Toast`(신규: 비동기 작업 피드백)
- `StatCard/KpiCard`, 차트(`AreaChart/DonutChart/BarChart` — 기존 SVG 컴포넌트 추출)
- 상태: `Loading/EmptyState/LoadError/Skeleton`(신규 스켈레톤)

## 5. 핵심 화면 레이아웃 (와이어프레임)

### 5.1 Dashboard
```
┌ Topbar: [☰] Bongsu      [⌘K 검색]        [range 7d|30d|90d] [theme] [user] ┐
├ Sidebar ┬─────────────────────────────────────────────────────────────────┤
│ Overview│  KPI: [열린취약점][Critical][KEV노출][SLA위반][에이전트 N/Total]   │
│ Security│  ┌ Findings over time (area) ─────────┐ ┌ Severity (donut) ──┐    │
│ Invent. │  └────────────────────────────────────┘ └────────────────────┘    │
│ Admin ▸ │  ┌ Top risk hosts (table) ───┐ ┌ Recent scans / activity ───┐     │
│         │  └───────────────────────────┘ └────────────────────────────┘     │
└─────────┴─────────────────────────────────────────────────────────────────┘
```

### 5.2 Vulnerabilities (리스트·트리아지 워크플로 최적화)
```
[필터바: 심각도▾ 상태▾ 호스트▾ KEV☐ 검색____ [적용][초기화]]   [선택 N건 ▸ 일괄 트리아지]
┌ DataTable (sticky header, 가상스크롤) ──────────────────────────────────────┐
│ ☐ │ Sev⚠ │ CVE        │ 패키지        │ 호스트수 │ EPSS │ KEV │ 상태   │ … │
│ ☐ │ 🔴C  │ CVE-2024-… │ openssl 1.1   │   12    │ 0.97 │ ●  │ open  │ ▸ │
└─────────────────────────────────────────────────────────────────────────────┘
우측 슬라이드오버(행 클릭): 요약·영향자산·트리아지 폼(상태/담당/사유) — 리스트 이탈 없이 처리
```

### 5.3 Host Detail
```
← Hosts   호스트명 [환경뱃지][criticality]              [스캔요청][그룹지정]
[탭: 개요 | 취약점 | 패키지 | 프로세스 | 포트]
┌ 개요: OS/커널/last-seen/에이전트상태  ┐ ┌ 심각도 분포(미니 도넛) ┐
└──────────────────────────────────────┘ └─────────────────────────┘
[취약점 탭 → §5.2 DataTable 재사용(host 스코프)]
```

### 5.4 Vulnerability Detail
```
← Vulns   CVE-2024-XXXX  [🔴Critical][KEV][EPSS 0.97]      [트리아지 ▾]
┌ 메타(CVSS 벡터/CWE/published/refs) ┐ ┌ AI 분석(요약·신뢰도) ┐
└────────────────────────────────────┘ └──────────────────────┘
┌ 영향 자산 (DataTable: 호스트·패키지·설치버전·수정버전) ┐
└─────────────────────────────────────────────────────────┘
```

## 6. 인터랙션·상태·접근성
- 모든 비동기: 로딩(스켈레톤) / 빈 / 에러(재시도) 상태 일관 컴포넌트. 변경 작업은 `Toast` 피드백.
- 키보드: ⌘K 팔레트, 테이블 행 ↑↓/Enter, 모달 포커스 트랩·Esc, 모든 인터랙티브 `:focus-visible` 링.
- ARIA: 아이콘 전용 버튼 `aria-label`, 테이블 `scope`, 심각도 아이콘 `title`/sr-only 텍스트. 색만으로 정보전달 금지(§2.3).
- 대비: 라이트/다크 모두 WCAG AA(텍스트 4.5:1) 검증.

## 7. 반응형·대용량 데이터
- `DataTable` 가상 스크롤(수만 행) — 자체 윈도잉 또는 `@tanstack/react-virtual`(경량, 트레이드오프: +의존성 vs 성능). 서버 페이지네이션 우선, 가상화는 클라이언트 표시 한정.
- 브레이크포인트: <820px 사이드바 → 상단 드로어, 테이블 → 카드/수평스크롤. 컨테이너 `max-width` 없이 풀뷰포트 유지(운영 콘솔).

## 8. 구현 아키텍처·단계별 마이그레이션
현행 단일 `App.tsx`(8,700줄) → 분해:
```
web/src/
  styles/tokens.css, base.css, components.css   # index.css 분해
  components/        # Button, DataTable, Modal, Severity, CommandPalette, charts…
  views/             # DashboardView.tsx, VulnsView.tsx, … (21뷰 1파일씩)
  hooks/             # useApi, useDebounce, useTheme, useHotkeys
  lib/               # api.ts(유지), format, verCmp(추출)
  router.tsx, App.tsx(셸: 라우터+사이드바+토픽바)
```
**마이그레이션(점진적, 파괴적 허용)**:
1. **UI.1 토큰 레이어**: `styles/tokens.css` 도입(기존 변수 alias 유지 → 무중단). 스페이싱/타입 스케일 적용 시작.
2. **UI.2 컴포넌트 추출**: `Button/Badge→Severity/Card/Modal/DataTable`를 `components/`로 분리, 기존 인라인을 대체.
3. **UI.3 라우팅+셸**: URL 라우터 + 토픽바(⌘K, 테마토글) + 사이드바 그룹 재편.
4. **UI.4 뷰 분해**: 21개 뷰를 `views/`로 1파일씩 이동, `DataTable`로 테이블 통일.
5. **UI.5 커맨드팔레트·스켈레톤·Toast·라이트모드** 마감.

## 9. 트레이드오프·기각된 대안
- **무거운 UI 라이브러리(MUI/Chakra/Ant) 기각**: 번들 증가·셀프호스트 폰트/스타일 충돌·기존 토큰과 이중화. 자체 컴포넌트 시스템 유지가 일관성·번들 우위.
- **react-router 도입 채택**(자체 hash 라우터 대비): 딥링크·중첩·뒤로가기 표준화 이득 > 경량 의존성 비용. (대안: 의존성 0 원하면 ~80줄 hash 라우터.)
- **가상화 라이브러리**: 서버 페이지네이션이 1차 방어. 클라 수만 행 표시 필요 화면만 선택 적용.
- **라이트 모드**: hue 기반 단일 팔레트(deepseek안)는 우아하나 기존 hex 보존과 충돌 → 모드별 semantic 매핑(명시적 hex)으로 채택, 안전·예측가능.
