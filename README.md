# lolog-auth

LOLog 인증 서비스(`/auth`). 이메일·소셜 가입과 로그인, 토큰 발급·갱신, 탈퇴를 맡는다.
API와 데이터 모양은 [LOLog-docs](https://github.com/LOLog-2026/LOLog-docs/tree/main/spec)가 기준이다.

## 로컬 실행

PostgreSQL·Redis는 lolog-api의 `compose.yaml`이 띄운 것을 같이 쓰고, DB만 `lolog_auth`로 따로 둔다.

1. lolog-api 폴더에서 `docker compose up -d`
2. 처음 한 번 DB를 만든다.

   ```bash
   docker compose -f <lolog-api 폴더>/compose.yaml exec postgres createdb -U myuser lolog_auth
   ```

3. `cp .env.example .env` 후 `POSTGRES_PASSWORD`, `JWT_SECRET`, `INTERNAL_TOKEN`에 lolog-api `.env`와 같은 값을 넣는다. `JWT_SECRET`이 같아야 여기서 받은 토큰이 lolog-api에서 통한다.
4. `./mvnw spring-boot:run -Dspring-boot.run.profiles=local` (포트 8081)

### 가입 인증번호 메일

- 로컬은 기본으로 메일을 보내지 않고, `POST /auth/email/code`를 부르면 인증번호를 콘솔에 찍는다(`[로컬 전용] 가입 인증번호: ...`).
- 실제로 보내 보려면 `.env`에서 `MAIL_LOG_ONLY=false`로 바꾸고 `MAIL_USERNAME`, `MAIL_PASSWORD`(Gmail 앱 비밀번호), `MAIL_FROM`을 넣는다.
- 배포(prod)는 늘 SMTP로 보낸다. `MAIL_HOST`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_FROM`이 없으면 서버가 뜨지 않는다.

## 테스트

`./mvnw test`. Testcontainers로 PostgreSQL·Redis를 띄우므로 Docker가 켜져 있어야 한다.
