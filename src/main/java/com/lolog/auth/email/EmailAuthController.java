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

	public EmailAuthController(EmailAuthService service) {
		this.service = service;
	}

	// POST /auth/signup → 201 TokenResponse
	@PostMapping("/auth/signup")
	@ResponseStatus(HttpStatus.CREATED)
	public TokenResponse signup(@Valid @RequestBody SignupRequest request) {
		return service.signup(request.email(), request.password());
	}

	// POST /auth/login → 200 TokenResponse
	@PostMapping("/auth/login")
	public TokenResponse login(@Valid @RequestBody LoginRequest request) {
		return service.login(request.email(), request.password());
	}

	// 가입 때는 이메일 형식(254자 이하)과 비밀번호 규칙(8~64자, 영문·숫자 포함)을 검사한다(api-dto.md 1장).
	public record SignupRequest(@NotBlank @Email @Size(max = 254) String email,
			@NotNull @Size(min = 8, max = 64) @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*[0-9]).*$") String password) {
	}

	// 로그인은 비밀번호 규칙을 검사하지 않는다. 값이 빠졌을 때만 400이다.
	public record LoginRequest(@NotBlank String email, @NotNull String password) {
	}

}
