package com.lolog.auth.user;

// 회원 권한(LOLog-docs PR #59 spec/admin.md 1장). 액세스 토큰의 role 클레임과 GET /auth/me의 role에 이 이름 그대로 쓴다.
public enum Role {

	USER, ADMIN

}
