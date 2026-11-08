package com.lolog.auth.token;

import com.lolog.auth.common.ApiException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

// 액세스 토큰을 검사한다. lolog-api(JwtAuthConfig)와 같은 규칙이다:
// 서명 HS256, typ = "access", sub = 숫자, iat 있음, exp가 지났으면(30초 여유) 만료.
@Component
public class AccessTokenVerifier {

	// 서버끼리 시계가 조금 달라도 방금 발급한 토큰이 거절되지 않게 둔다(lolog-api와 같은 값).
	static final Duration CLOCK_SKEW = Duration.ofSeconds(30);

	private final NimbusJwtDecoder decoder;

	private final Clock clock;

	public AccessTokenVerifier(@Value("${lolog.auth.jwt-secret}") String secret, Clock clock) {
		SecretKey key = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
		this.decoder = NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();
		// 만료는 직접 따로 본다. 기본 검사는 만료도 "틀린 토큰"과 같은 오류로 묶기 때문이다.
		this.decoder.setJwtValidator(jwt -> org.springframework.security.oauth2.core.OAuth2TokenValidatorResult.success());
		this.clock = clock;
	}

	// "Bearer <토큰>" 헤더 값을 받아 회원 ID를 돌려준다.
	public long verify(String authorization) {
		if (authorization == null || !authorization.startsWith("Bearer ")) {
			throw invalid();
		}
		Jwt jwt;
		try {
			jwt = decoder.decode(authorization.substring("Bearer ".length()).trim());
		}
		catch (JwtException e) {
			throw invalid();
		}
		String sub = jwt.getSubject();
		if (!"access".equals(jwt.getClaimAsString("typ")) || sub == null || !sub.matches("\\d{1,18}")
				|| jwt.getIssuedAt() == null || jwt.getExpiresAt() == null) {
			throw invalid();
		}
		Instant exp = jwt.getExpiresAt();
		if (clock.instant().minus(CLOCK_SKEW).isAfter(exp)) {
			throw new ApiException(HttpStatus.UNAUTHORIZED, "TOKEN_EXPIRED", "액세스 토큰이 만료됐습니다.");
		}
		return Long.parseLong(sub);
	}

	private static ApiException invalid() {
		return new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_TOKEN", "액세스 토큰이 없거나 올바르지 않습니다.");
	}

}
