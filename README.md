# VIBE SECURITY

ZIP 파일 안의 코드를 브라우저에서 살펴보고, 확인이 필요한 부분과 쉬운 수정 방향을 보여주는 보안 예비진단 도구입니다.

## Cloudflare 배포

이 저장소는 Cloudflare Workers Static Assets 방식으로 구성되어 있습니다. 프로젝트 루트는 `/`, 배포 명령은 `npx wrangler deploy`입니다. `wrangler.jsonc`가 `public/` 폴더를 정적 파일 폴더로 지정하므로 `Could not detect a directory containing static files` 오류를 피할 수 있습니다.

Cloudflare의 `vibe-security` Worker에 `GEMINI_API_KEY`를 Secret으로 설정해 주세요. 키를 소스 코드, `wrangler.jsonc`, GitHub에 적지 마세요. 이미 해당 Worker에 Secret으로 등록되어 있다면 다시 추가할 필요는 없습니다.

## Gemini 요약과 파일 보호

ZIP 파일과 코드 내용은 브라우저에서만 검사합니다. 사용자가 `Gemini로 요약하기`를 눌렀을 때도 ZIP, 코드 일부, 파일 이름은 보내지 않습니다. 점검 항목의 종류와 심각도만 Gemini로 보내 쉬운 요약을 받습니다.

AI 요약 요청은 Cloudflare Rate Limit 설정으로 IP당 분당 5회로 제한합니다. 이 제한은 비용 보호를 위한 기본 장치이며, 전 세계에서 합산되는 엄격한 한도는 아닙니다. 사용량과 비용을 Cloudflare 및 Gemini 화면에서 확인해 주세요.

## 로컬 미리보기

```sh
npx wrangler dev
```

로컬에서 Gemini 기능을 쓸 때는 `.dev.vars` 파일에 `GEMINI_API_KEY=...`를 넣을 수 있습니다. `.dev.vars`는 Git에 올라가지 않도록 제외되어 있습니다.
