package com.lolog.auth.social;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

// 구글 ID 토큰(JWT)을 구글 공개 키로 확인한다. 앱이 Credential Manager에 웹 클라이언트 ID를 serverClientId로 넘겨 받은 토큰이라
// aud가 웹 클라이언트 ID여야 한다(api-dto.md SocialLoginRequest). 공개 키는 NimbusJwtDecoder가 받아 두고 다시 쓴다.
@Component
public class GoogleIdTokenVerifier {

	private static final Set<String> ISSUERS = Set.of("https://accounts.google.com", "accounts.google.com");

	private final NimbusJwtDecoder decoder;

	private final String clientId;

	public GoogleIdTokenVerifier(@Value("${lolog.social.google.client-id}") String clientId,
			@Value("${lolog.social.google.jwk-set-uri}") String jwkSetUri, Clock clock) {
		this.clientId = clientId;
		SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
		requestFactory.setConnectTimeout(Duration.ofSeconds(3));
		requestFactory.setReadTimeout(Duration.ofSeconds(5));
		this.decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).restOperations(new RestTemplate(requestFactory)).build();
		JwtTimestampValidator timestamps = new JwtTimestampValidator();
		timestamps.setClock(clock);
		this.decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(timestamps, jwt -> check(jwt)));
	}

	// 서명·만료·발급자·aud가 틀리면 InvalidProviderTokenException. 공개 키를 받지 못하면 다른 예외(500)다.
	public SocialProfile verify(String idToken) {
		// 웹 클라이언트 ID가 설정되지 않았으면 어떤 토큰도 받지 않는다.
		if (clientId.isBlank()) {
			throw new InvalidProviderTokenException("구글 웹 클라이언트 ID가 설정되지 않았습니다.");
		}
		Jwt jwt;
		try {
			jwt = decoder.decode(idToken);
		}
		catch (BadJwtException e) {
			throw new InvalidProviderTokenException("구글 ID 토큰이 올바르지 않습니다.");
		}
		// 구글이 인증한 이메일만 받는다. 인증 안 된 이메일로는 남의 이메일을 차지할 수 있다.
		Object verified = jwt.getClaim("email_verified");
		boolean emailVerified = Boolean.TRUE.equals(verified) || "true".equals(verified);
		String email = jwt.getClaimAsString("email");
		return new SocialProfile(jwt.getSubject(), emailVerified ? email : null);
	}

	private OAuth2TokenValidatorResult check(Jwt jwt) {
		String issuer = jwt.getClaimAsString("iss");
		List<String> audience = jwt.getAudience();
		if (issuer == null || !ISSUERS.contains(issuer)) {
			return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "발급자가 구글이 아닙니다.", null));
		}
		if (audience == null || !audience.contains(clientId)) {
			return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "우리 앱의 토큰이 아닙니다.", null));
		}
		if (jwt.getSubject() == null || jwt.getSubject().isBlank()) {
			return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "sub가 없습니다.", null));
		}
		return OAuth2TokenValidatorResult.success();
	}

}
