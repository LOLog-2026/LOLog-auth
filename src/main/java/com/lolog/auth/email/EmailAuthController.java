package com.lolog.auth.email;

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

@RestController
public class EmailAuthController {

	private final EmailAuthService service;

	private final EmailVerificationService verification;

	public EmailAuthController(EmailAuthService service, EmailVerificationService verification) {
		this.service = service;
		this.verification = verification;
	}

	// POST /auth/email/code → 204. 가입 여부와 관계없이 같은 응답이다.
	@PostMapping("/auth/email/code")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void sendCode(@Valid @RequestBody EmailCodeRequest request) {
		verification.sendCode(request.email());
	}

	// POST /auth/signup → 201 TokenResponse
	@PostMapping("/auth/signup")
	@ResponseStatus(HttpStatus.CREATED)
	public TokenResponse signup(@Valid @RequestBody SignupRequest request) {
		return service.signup(request.email(), request.password(), request.code());
	}

	// POST /auth/login → 200 TokenResponse
	@PostMapping("/auth/login")
	public TokenResponse login(@Valid @RequestBody LoginRequest request) {
		return service.login(request.email(), request.password());
	}

	public record EmailCodeRequest(@NotBlank @Email @Size(max = 254) String email) {
	}

	// 가입 때는 이메일 형식(254자 이하)과 비밀번호 규칙(8~64자, 영문·숫자 포함), 인증번호(6자리 숫자)를 검사한다(api-dto.md 1장).
	public record SignupRequest(@NotBlank @Email @Size(max = 254) String email,
			@NotNull @Size(min = 8, max = 64) @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*[0-9]).*$") String password,
			@NotNull @Pattern(regexp = "^[0-9]{6}$") String code) {
	}

	// 로그인도 이메일 형식(254자 이하)은 가입과 같게 검사한다(LOLog-docs PR #60). 비밀번호 규칙은 검사하지 않고,
	// 값이 빠졌을 때만 400이다(규칙이 바뀌기 전에 만든 비밀번호로도 로그인되게).
	public record LoginRequest(@NotBlank @Email @Size(max = 254) String email, @NotNull String password) {
	}

}
