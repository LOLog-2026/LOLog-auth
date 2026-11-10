package com.lolog.auth.email;

import com.lolog.auth.common.ApiException;
import com.lolog.auth.common.SafeLog;
import com.lolog.auth.email.EmailCodeStore.Purpose;
import com.lolog.auth.token.RefreshTokenStore;
import com.lolog.auth.token.TokenResponse;
import com.lolog.auth.token.TokenService;
import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

// 비밀번호 찾기·바꾸기(FR-AUTH-07, api-spec.md "비밀번호 찾기 인증번호").
// 소셜로만 가입해 비밀번호가 없는 계정은 대상이 아니다. 비밀번호를 바꾸면 그 회원의 리프레시 토큰을 모두 지운다.
@Service
public class PasswordService {

	private static final Logger log = LoggerFactory.getLogger(PasswordService.class);

	private final SecureRandom random = new SecureRandom();

	private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

	private final EmailCodeStore codes;

	private final VerificationMailer mailer;

	private final UserRepository users;

	private final RefreshTokenStore refreshTokens;

	private final TokenService tokens;

	private final Executor mailExecutor;

	public PasswordService(EmailCodeStore codes, VerificationMailer mailer, UserRepository users,
			RefreshTokenStore refreshTokens, TokenService tokens,
			@Qualifier(PasswordResetMailConfig.EXECUTOR) Executor mailExecutor) {
		this.codes = codes;
		this.mailer = mailer;
		this.users = users;
		this.refreshTokens = refreshTokens;
		this.tokens = tokens;
		this.mailExecutor = mailExecutor;
	}

	// 60초 간격만 확인하고 바로 돌아간다(204). 가입 여부는 응답 내용으로도 시간으로도 드러나지 않는다.
	// 메일은 뒤에서 보낸다: 비밀번호가 있는 계정이면 번호, 소셜로만 가입한 계정이면 안내, 가입 안 됐으면 아무것도 보내지 않는다.
	public void requestResetCode(String email) {
		String normalized = User.normalizeEmail(email);
		if (!codes.tryStartCooldown(Purpose.PASSWORD_RESET, normalized)) {
			throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "TOO_MANY_REQUESTS", "잠시 뒤에 다시 요청해 주세요.");
		}
		try {
			mailExecutor.execute(() -> sendResetMail(normalized));
		}
		catch (RejectedExecutionException e) {
			// 대기열이 꽉 찼다(TaskRejectedException도 이 예외다). 간격을 풀고 500으로 돌려보내 다시 받게 한다.
			codes.clearCooldown(Purpose.PASSWORD_RESET, normalized);
			throw e;
		}
	}

	void sendResetMail(String email) {
		try {
			Optional<User> user = users.findByEmailAndDeletedAtIsNull(email);
			if (user.isEmpty()) {
				return;
			}
			if (user.get().getPasswordHash() == null) {
				codes.delete(Purpose.PASSWORD_RESET, email);
				mailer.sendPasswordResetSocialOnly(email);
				return;
			}
			String code = "%06d".formatted(random.nextInt(1_000_000));
			codes.save(Purpose.PASSWORD_RESET, email, code);
			mailer.sendPasswordResetCode(email, code);
		}
		catch (RuntimeException e) {
			// 앱은 이미 204를 받았다. 번호와 간격을 지워 바로 다시 받을 수 있게 하고 로그만 남긴다(이메일은 남기지 않는다).
			codes.delete(Purpose.PASSWORD_RESET, email);
			codes.clearCooldown(Purpose.PASSWORD_RESET, email);
			log.warn("비밀번호 찾기 메일을 보내지 못했다", SafeLog.withoutMessages(e));
		}
	}

	// 인증번호가 맞으면 새 비밀번호로 바꾸고 그 회원의 로그인을 모두 끊는다.
	// 틀리면 400 INVALID_CODE, 없음·만료·5번 틀림이면 400 CODE_EXPIRED.
	// 번호를 받은 뒤 탈퇴했거나 비밀번호가 없는 계정이 됐으면 번호를 쓸 곳이 없으므로 CODE_EXPIRED다.
	// Redis(토큰 지우기)가 실패하면 비밀번호 변경도 되돌린다.
	@Transactional
	public void resetPassword(String email, String code, String newPassword) {
		checkLength("newPassword", newPassword);
		String normalized = User.normalizeEmail(email);
		switch (codes.check(Purpose.PASSWORD_RESET, normalized, code)) {
			case MATCHED -> {
			}
			case WRONG -> throw new ApiException(HttpStatus.BAD_REQUEST, "INVALID_CODE", "인증번호가 맞지 않습니다.");
			case EXPIRED -> throw codeExpired();
		}
		User user = users.findByEmailAndDeletedAtIsNull(normalized)
			.filter(u -> u.getPasswordHash() != null)
			.orElseThrow(PasswordService::codeExpired);
		user.changePassword(passwordEncoder.encode(newPassword));
		users.saveAndFlush(user);
		refreshTokens.revokeAll(user.getId());
	}

	// 지금 비밀번호가 맞으면 바꾸고, 다른 기기의 로그인을 끊은 뒤 이 기기에 새 토큰 한 벌을 준다.
	// 지금 비밀번호가 틀리면 401 INVALID_CREDENTIALS, 비밀번호가 없는 계정이면 400 INVALID_REQUEST(currentPassword).
	@Transactional
	public TokenResponse changePassword(long userId, String currentPassword, String newPassword) {
		User user = users.findByIdAndDeletedAtIsNull(userId)
			.orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_TOKEN", "회원이 없습니다."));
		if (user.getPasswordHash() == null) {
			throw ApiException.invalid("currentPassword", "비밀번호가 없는 계정입니다.");
		}
		checkLength("newPassword", newPassword);
		boolean tooLong = currentPassword.getBytes(StandardCharsets.UTF_8).length > EmailAuthService.BCRYPT_MAX_BYTES;
		if (tooLong || !passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
			throw new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "지금 비밀번호가 맞지 않습니다.");
		}
		user.changePassword(passwordEncoder.encode(newPassword));
		users.saveAndFlush(user);
		refreshTokens.revokeAll(userId);
		return tokens.issue(userId);
	}

	// BCrypt는 72바이트까지만 받는다(EmailAuthService.signup과 같은 검사).
	private static void checkLength(String field, String password) {
		if (password.getBytes(StandardCharsets.UTF_8).length > EmailAuthService.BCRYPT_MAX_BYTES) {
			throw ApiException.invalid(field, "비밀번호가 너무 깁니다.");
		}
	}

	private static ApiException codeExpired() {
		return new ApiException(HttpStatus.BAD_REQUEST, "CODE_EXPIRED", "인증번호를 다시 받아 주세요.");
	}

}
