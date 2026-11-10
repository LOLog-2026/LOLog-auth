package com.lolog.auth.email;

import com.lolog.auth.common.ApiException;
import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import java.security.SecureRandom;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

// 가입 인증번호 보내기와 확인(FR-AUTH-01, api-spec.md "가입 인증번호").
@Service
public class EmailVerificationService {

	private final SecureRandom random = new SecureRandom();

	private final EmailCodeStore codes;

	private final VerificationMailer mailer;

	private final UserRepository users;

	public EmailVerificationService(EmailCodeStore codes, VerificationMailer mailer, UserRepository users) {
		this.codes = codes;
		this.mailer = mailer;
		this.users = users;
	}

	// 응답으로는 가입 여부를 알리지 않는다. 가입 안 된 이메일에는 번호를, 가입된 이메일에는 안내를 메일로 보낸다.
	// 같은 이메일로 60초 안에 다시 부르면 429 TOO_MANY_REQUESTS. 메일을 보내지 못하면 간격을 풀고 예외를 그대로 던진다(500).
	public void sendCode(String email) {
		String normalized = User.normalizeEmail(email);
		if (!codes.tryStartCooldown(normalized)) {
			throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "TOO_MANY_REQUESTS", "잠시 뒤에 다시 요청해 주세요.");
		}
		boolean registered = users.existsByEmailAndDeletedAtIsNull(normalized);
		try {
			if (registered) {
				// 번호가 남아 있으면 지운다. 가입된 이메일로는 번호를 쓸 일이 없다.
				codes.delete(normalized);
				mailer.sendAlreadyRegistered(normalized);
			}
			else {
				String code = "%06d".formatted(random.nextInt(1_000_000));
				codes.save(normalized, code);
				mailer.sendCode(normalized, code);
			}
		}
		catch (RuntimeException e) {
			codes.delete(normalized);
			codes.clearCooldown(normalized);
			throw e;
		}
	}

	// 맞으면 번호를 지우고 넘어간다. 틀리면 400 INVALID_CODE, 없음·만료·5번 틀림이면 400 CODE_EXPIRED.
	public void verify(String email, String code) {
		switch (codes.check(User.normalizeEmail(email), code)) {
			case MATCHED -> {
			}
			case WRONG -> throw new ApiException(HttpStatus.BAD_REQUEST, "INVALID_CODE", "인증번호가 맞지 않습니다.");
			case EXPIRED -> throw new ApiException(HttpStatus.BAD_REQUEST, "CODE_EXPIRED", "인증번호를 다시 받아 주세요.");
		}
	}

}
