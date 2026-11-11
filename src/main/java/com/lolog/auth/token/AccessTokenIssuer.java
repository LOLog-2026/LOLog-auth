package com.lolog.auth.token;

import com.lolog.auth.user.Role;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

// 액세스 토큰(JWT)을 만든다(api-dto.md "토큰").
// 서명 HS256, 비밀값 JWT_SECRET(32바이트 이상)은 lolog-api와 같다. 클레임은 sub(사용자 ID 문자열), typ="access", iat, exp,
// role(USER·ADMIN). lolog-api는 role로 /api/admin/**을 막는다(LOLog-docs PR #59 spec/admin.md 1장).
@Component
public class AccessTokenIssuer {

	public static final Duration VALIDITY = Duration.ofMinutes(30);

	private static final int MIN_SECRET_BYTES = 32;

	private final MACSigner signer;

	private final Clock clock;

	public AccessTokenIssuer(@Value("${lolog.auth.jwt-secret}") String secret, Clock clock) {
		// lolog-api와 같게 문자열을 UTF-8 바이트로 쓴다. 짧으면 서버를 띄우지 않는다.
		byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
		if (bytes.length < MIN_SECRET_BYTES) {
			throw new IllegalStateException("JWT_SECRET은 32바이트 이상이어야 합니다.");
		}
		try {
			this.signer = new MACSigner(bytes);
		}
		catch (JOSEException e) {
			throw new IllegalStateException("JWT_SECRET으로 서명기를 만들 수 없습니다.", e);
		}
		this.clock = clock;
	}

	public String issue(long userId, Role role) {
		// JWT 시각은 초 단위라 밀리초를 버린다. exp = iat + 1800
		Instant now = clock.instant().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
		JWTClaimsSet claims = new JWTClaimsSet.Builder().subject(Long.toString(userId))
			.claim("typ", "access")
			.claim("role", role.name())
			.issueTime(Date.from(now))
			.expirationTime(Date.from(now.plus(VALIDITY)))
			.build();
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
		try {
			jwt.sign(signer);
		}
		catch (JOSEException e) {
			throw new IllegalStateException("액세스 토큰에 서명하지 못했습니다.", e);
		}
		return jwt.serialize();
	}

}
