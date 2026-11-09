package com.lolog.auth.email;

// 가입 인증 메일을 보낸다. 배포는 SMTP(SmtpVerificationMailer), 로컬은 콘솔 출력(LogOnlyVerificationMailer)이다.
public interface VerificationMailer {

	// 가입 안 된 이메일에 6자리 인증번호를 보낸다.
	void sendCode(String email, String code);

	// 이미 가입된 이메일에 번호 대신 안내를 보낸다. 앱에는 어느 쪽인지 알리지 않는다.
	void sendAlreadyRegistered(String email);

}
