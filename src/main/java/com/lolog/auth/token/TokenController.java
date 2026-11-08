package com.lolog.auth.token;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenController {

	private final TokenService tokens;

	public TokenController(TokenService tokens) {
		this.tokens = tokens;
	}

	// POST /auth/refresh → 200 TokenResponse
	@PostMapping("/auth/refresh")
	public TokenResponse refresh(@Valid @RequestBody RefreshRequest request) {
		return tokens.refresh(request.refreshToken());
	}

	// POST /auth/logout → 204
	@PostMapping("/auth/logout")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void logout(@Valid @RequestBody RefreshRequest request) {
		tokens.logout(request.refreshToken());
	}

	// RefreshRequest · LogoutRequest (api-dto.md 1장). 두 요청의 모양이 같아 하나로 쓴다.
	public record RefreshRequest(@NotBlank String refreshToken) {
	}

}
