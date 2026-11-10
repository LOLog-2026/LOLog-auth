package com.lolog.auth.email;

import com.lolog.auth.common.ApiException;
import com.lolog.auth.token.TokenResponse;
import com.lolog.auth.token.TokenService;
import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.Optional;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

// 이메일 가입·로그인(FR-AUTH-01).
@Service
public class EmailAuthService {

	private static final int BCRYPT_MAX_BYTES = 72;

	private final UserRepository users;

	private final TokenService tokens;

	private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

	// 없는 이메일로 로그인할 때도 비밀번호 비교 시간을 들여, 응답 시간으로 가입 여부를 알 수 없게 한다.
	private final String dummyHash = passwordEncoder.encode("dummy-password-for-timing");

	private final Clock clock;

	private final EmailVerificationService verification;

	public EmailAuthService(UserRepository users, TokenService tokens, Clock clock,
			EmailVerificationService verification) {
		this.users = users;
		this.tokens = tokens;
		this.clock = clock;
		this.verification = verification;
	}

	// 인증번호를 먼저 확인하고(틀림 400 INVALID_CODE, 없음·만료 400 CODE_EXPIRED), 맞을 때만 가입 여부를 본다.
	// 그래서 번호를 받을 수 없는 남은 409로 가입 여부를 알아낼 수 없다.
	// 이미 가입된 이메일(소셜 가입 포함)이면 409 ACCOUNT_EXISTS. 탈퇴한 계정의 이메일로는 다시 가입할 수 있다.
	public TokenResponse signup(String email, String password, String code) {
		// BCrypt는 72바이트까지만 받는다. 64자 안이어도 한글처럼 여러 바이트인 글자가 많으면 넘을 수 있다.
		if (password.getBytes(StandardCharsets.UTF_8).length > BCRYPT_MAX_BYTES) {
			throw ApiException.invalid("password", "비밀번호가 너무 깁니다.");
		}
		String normalized = User.normalizeEmail(email);
		verification.verify(normalized, code);
		if (users.existsByEmailAndDeletedAtIsNull(normalized)) {
			throw accountExists();
		}
		User user;
		try {
			user = users.saveAndFlush(
					User.withPassword(normalized, passwordEncoder.encode(password), OffsetDateTime.now(clock)));
		}
		catch (DataIntegrityViolationException e) {
			// 같은 이메일로 동시에 가입하면 DB의 유니크 제약이 하나만 남긴다.
			throw accountExists();
		}
		return tokens.issue(user.getId());
	}

	// 이메일이나 비밀번호가 틀리면 401 INVALID_CREDENTIALS. 어느 쪽이 틀렸는지는 알리지 않는다.
	// 소셜로만 가입한 계정(비밀번호 없음)도 같은 오류다.
	public TokenResponse login(String email, String password) {
		Optional<User> user = users.findByEmailAndDeletedAtIsNull(User.normalizeEmail(email));
		String hash = user.map(User::getPasswordHash).orElse(null);
		// 72바이트를 넘는 비밀번호로는 가입할 수 없으므로 비교하지 않고 틀린 것으로 본다.
		boolean tooLong = password.getBytes(StandardCharsets.UTF_8).length > BCRYPT_MAX_BYTES;
		boolean matches = !tooLong && passwordEncoder.matches(password, hash != null ? hash : dummyHash);
		if (hash == null || !matches) {
			throw new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "이메일 또는 비밀번호가 맞지 않습니다.");
		}
		return tokens.issue(user.get().getId());
	}

	private static ApiException accountExists() {
		return new ApiException(HttpStatus.CONFLICT, "ACCOUNT_EXISTS", "이미 가입된 이메일입니다.");
	}

}
