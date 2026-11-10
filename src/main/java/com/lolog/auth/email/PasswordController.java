package com.lolog.auth.email;

import com.lolog.auth.token.CurrentUser;
import com.lolog.auth.token.TokenResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

// 비밀번호 찾기·바꾸기(FR-AUTH-07)
@RestController
public class PasswordController {

	private final PasswordService service;

	public PasswordController(PasswordService service) {
		this.service = service;
	}

	// POST /auth/password/reset/code → 204. 가입 여부와 관계없이 바로 같은 응답이다.
	@PostMapping("/auth/password/reset/code")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void requestResetCode(@Valid @RequestBody PasswordResetCodeRequest request) {
		service.requestResetCode(request.email());
	}

	// POST /auth/password/reset → 204
	@PostMapping("/auth/password/reset")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void resetPassword(@Valid @RequestBody PasswordResetRequest request) {
		service.resetPassword(request.email(), request.code(), request.newPassword());
	}

	// POST /auth/me/password → 200 TokenResponse. 액세스 토큰을 먼저 확인한다(@CurrentUser가 첫 인자).
	@PostMapping("/auth/me/password")
	public TokenResponse changePassword(@CurrentUser Long userId, @Valid @RequestBody PasswordChangeRequest request) {
		return service.changePassword(userId, request.currentPassword(), request.newPassword());
	}

	// api-dto.md 1장
	public record PasswordResetCodeRequest(@NotBlank @Email @Size(max = 254) String email) {
	}

	// 새 비밀번호 규칙은 가입과 같다(8~64자, 영문·숫자 포함).
	public record PasswordResetRequest(@NotBlank @Email @Size(max = 254) String email,
			@NotNull @Pattern(regexp = "^[0-9]{6}$") String code,
			@NotNull @Size(min = 8, max = 64) @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*[0-9]).*$") String newPassword) {
	}

	// 지금 비밀번호는 규칙을 검사하지 않는다(로그인과 같다).
	public record PasswordChangeRequest(@NotNull String currentPassword,
			@NotNull @Size(min = 8, max = 64) @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*[0-9]).*$") String newPassword) {
	}

}
