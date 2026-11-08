package com.lolog.auth.token;

import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;

// 테스트에서 발급된 액세스 토큰을 시험용 비밀값(src/test/resources/application.properties)으로 검사한다.
public final class AccessTokens {

	public static final String SECRET = "test-jwt-secret-at-least-32-bytes-long!!";

	private AccessTokens() {
	}

	// 서명이 맞으면 클레임을, 틀리면 예외를 던진다.
	public static JWTClaimsSet verify(String token, String secret) throws Exception {
		SignedJWT jwt = SignedJWT.parse(token);
		if (!jwt.verify(new MACVerifier(secret.getBytes(StandardCharsets.UTF_8)))) {
			throw new IllegalStateException("서명이 맞지 않습니다.");
		}
		return jwt.getJWTClaimsSet();
	}

}
