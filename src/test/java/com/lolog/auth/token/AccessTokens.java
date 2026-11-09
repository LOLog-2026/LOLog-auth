package com.lolog.auth.token;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

// 테스트에서 발급된 액세스 토큰을 시험용 비밀값(src/test/resources/application.properties)으로 검사한다.
public final class AccessTokens {

	public static final String SECRET = "test-jwt-secret-at-least-32-bytes-long!!";

	private AccessTokens() {
	}

	// 원하는 클레임으로 토큰을 직접 만든다. null인 클레임은 넣지 않는다.
	public static String token(String sub, String typ, Instant iat, Instant exp, String secret) throws Exception {
		JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().subject(sub);
		if (typ != null) {
			claims.claim("typ", typ);
		}
		if (iat != null) {
			claims.issueTime(Date.from(iat));
		}
		if (exp != null) {
			claims.expirationTime(Date.from(exp));
		}
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims.build());
		jwt.sign(new MACSigner(secret.getBytes(StandardCharsets.UTF_8)));
		return jwt.serialize();
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
