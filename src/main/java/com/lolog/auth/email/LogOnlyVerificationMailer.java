package com.lolog.auth.email;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

// 로컬 전용. 메일을 보내지 않고 인증번호를 콘솔에 찍는다. Gmail 계정 없이도 가입을 시험할 수 있게 한다.
// lolog.mail.log-only=true일 때만 쓰고, 배포 설정(application-prod.yml)에서는 켜지 않는다. 이메일은 찍지 않는다.
@Component
@ConditionalOnProperty(name = "lolog.mail.log-only", havingValue = "true")
public class LogOnlyVerificationMailer implements VerificationMailer {

	private static final Logger log = LoggerFactory.getLogger(LogOnlyVerificationMailer.class);

	@Override
	public void sendCode(String email, String code) {
		log.info("[로컬 전용] 가입 인증번호: {}", code);
	}

	@Override
	public void sendAlreadyRegistered(String email) {
		log.info("[로컬 전용] 이미 가입된 이메일이라 안내 메일을 보낼 차례");
	}

}
