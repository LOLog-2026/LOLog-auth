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

3. `cp .env.example .env` 후 `POSTGRES_PASSWORD`에 lolog-api `.env`와 같은 값을 넣는다.
4. `./mvnw spring-boot:run -Dspring-boot.run.profiles=local` (포트 8081)

## 테스트

`./mvnw test`. Testcontainers로 PostgreSQL·Redis를 띄우므로 Docker가 켜져 있어야 한다.
