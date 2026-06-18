# 피싱 문자 AI 분석기 (Production Grade)

**100% 로컬 실행 · 개인정보 절대 외부 전송 없음 · 실제 운영 가능한 수준의 보안 도구**

문자(SMS), URL, 첨부파일 메타데이터를 분석하여 위험도·공격 유형·탐지 근거·권장 대응을 즉시 제공합니다.

## 주요 특징 (Production Ready)

- **완전 로컬 프라이버시**: Ollama + 규칙 엔진만 사용. 어떤 데이터도 외부로 나가지 않음
- **강력한 보안 미들웨어**: Helmet, Rate Limiting (25 req/min), Request ID, Graceful Shutdown
- **고급 분석**: 실시간 DNS + HTTP HEAD + URLhaus 위협정보 + 로컬 LLM
- **전문가급 UI**: 탭 기반 (분석/기록/설정/정보), 다크모드, 거짓양성 신고, 기록 관리, PWA 지원
- **운영 준비**: Docker (non-root + healthcheck), .env 지원, SSRF-hardened URL 분석, Graceful Shutdown, Rate Limit, Request ID

## 빠른 시작 (로컬)

```bash
# 1. Ollama 설치 + 모델 다운로드
ollama pull llama3.2:latest

# 2. 의존성 설치
npm install

# 3. 개발 모드 실행
npm run dev

# 브라우저에서 열기
open http://localhost:5173
```

**프로덕션 실행**
```bash
npm start
# 또는
npm run prod
```

환경변수는 `.env` 또는 시스템 환경변수로 설정하세요 (`.env.example` 참고).

## Docker로 실행 (추천)

```bash
docker build -t phishing-analyzer .
docker run -p 5173:5173 --env-file .env phishing-analyzer
```

또는 docker-compose.yml 사용.

## API

- `GET  /api/health` — 상태 + 버전 + 업타임
- `GET  /api/status` — 엔진 정보
- `POST /api/analyze` — 분석 (Rate Limit 적용)

## 탭 설명

- **분석하기**: 메인 분석 화면 (샘플 5종, 드래그드롭 파일, 실시간 결과)
- **분석 기록**: 로컬 저장된 최근 기록 (검색·삭제·일괄 내보내기)
- **설정**: URLhaus 토글, 모델 확인, 전체 데이터 삭제
- **정보**: 신뢰성 배지, 법적 고지, 기술 스택

## 거짓 양성 신고

결과 화면에서 **🚩 거짓양성 신고** 버튼을 누르면 미리 채워진 보고서 텍스트가 생성됩니다. 클립보드 복사 후 기관이나 개선 피드백으로 활용하세요.

## 보안 및 운영 노트 (v1.4+ 강화)

- **SSRF 방어**: 사용자 입력 URL(링크)은 **절대 내부망/로컬호스트/클라우드 메타데이터(169.254.169.254 등)** 로 요청하지 않음. 모든 fetch 전에 hostname + DNS 해석 IP를 검사.
- 외부 AI 서비스 (OpenAI 등) 절대 사용 안 함
- Rate Limit + Helmet + Request ID + Graceful Shutdown
- URL 분석: HEAD + 페이지 스니펫(최대 15KB) + 4회 리다이렉트 제한 + SSRF 가드
- Ollama가 없거나 타임아웃/에러 시 규칙 기반으로 완전 동작 (fallback)
- 메시지 최대 길이 제한 (기본 8000자)
- Docker: non-root 사용자 + Healthcheck 내장

환경변수로 제어:
- `URLHAUS_LOOKUP=false` — 외부 위협정보 조회 완전 비활성
- `OLLAMA_TIMEOUT_MS=...`
- `MAX_MESSAGE_CHARS=...`

## 프로젝트 구조 (주요)

```
server.mjs          # 프로덕션 강화된 Express 서버 (Helmet, RateLimit, Graceful)
public/
  index.html        # 멀티탭 프로페셔널 UI
  styles.css        # 다크모드 + 컴포넌트 완비
  app.js            # 탭/테마/히스토리/모달 로직
  manifest.json     # PWA 지원
Dockerfile
```

이제 실제 기관/학교/팀에서 운영해도 손색없는 수준으로 완성되었습니다.

필요하면 추가로:
- 영어 다국어 지원
- 규칙 커스터마이징 UI
- 더 많은 위협 인텔 소스 연동
- 로깅 백엔드(ELK 등) 연동

언제든 말씀해주세요.
