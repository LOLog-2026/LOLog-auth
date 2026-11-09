package com.lolog.auth.social;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.lolog.auth.common.ApiException;
import com.lolog.auth.token.CurrentUser;
import com.lolog.auth.user.SocialProvider;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.List;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SocialAuthController {

	private final SocialAuthService service;

	public SocialAuthController(SocialAuthService service) {
		this.service = service;
	}

	// POST /auth/social/{provider} → 200 TokenResponse + isNewUser
	@PostMapping("/auth/social/{provider}")
	public SocialLoginResponse login(@PathVariable String provider, @Valid @RequestBody SocialLoginRequest request) {
		SocialAuthService.Result result = service.login(provider(provider), request.providerToken());
		return new SocialLoginResponse(result.tokens().accessToken(), result.tokens().refreshToken(),
				result.tokens().accessTokenExpiresIn(), result.newUser());
	}

	// POST /auth/me/social/{provider} → 200 { linkedProviders }. 액세스 토큰을 먼저 확인한다(@CurrentUser가 첫 인자).
	@PostMapping("/auth/me/social/{provider}")
	public LinkedProvidersResponse link(@CurrentUser Long userId, @PathVariable String provider,
			@Valid @RequestBody SocialLoginRequest request) {
		return new LinkedProvidersResponse(service.link(userId, provider(provider), request.providerToken()));
	}

	// 주소의 provider는 소문자 google, naver만 받는다. 그 밖(kakao 포함)은 400 INVALID_REQUEST.
	private static SocialProvider provider(String value) {
		return SocialProvider.fromPath(value)
			.orElseThrow(() -> ApiException.invalid("provider", "지원하지 않는 소셜 로그인입니다."));
	}

	// SocialLoginRequest (api-dto.md 1장)
	public record SocialLoginRequest(@NotBlank String providerToken) {
	}

	// TokenResponse에 isNewUser가 붙은 모양(api-dto.md TokenResponse)
	public record SocialLoginResponse(String accessToken, String refreshToken, int accessTokenExpiresIn,
			@JsonProperty("isNewUser") boolean isNewUser) {
	}

	// POST /auth/me/social/{provider} 200 (MeResponse의 한 필드)
	public record LinkedProvidersResponse(List<String> linkedProviders) {
	}

}
