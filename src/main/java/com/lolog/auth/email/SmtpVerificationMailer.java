package com.lolog.auth.email;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

// SMTP(Gmail)로 가입 인증 메일을 보낸다. 접속 정보는 spring.mail.*(MAIL_HOST 등, deployment.md 4장)다.
@Component
@ConditionalOnProperty(name = "lolog.mail.log-only", havingValue = "false", matchIfMissing = true)
public class SmtpVerificationMailer implements VerificationMailer {

	private final JavaMailSender sender;

	private final String from;

	public SmtpVerificationMailer(JavaMailSender sender, @Value("${lolog.mail.from}") String from) {
		this.sender = sender;
		this.from = from;
	}

	@Override
	public void sendCode(String email, String code) {
		send(email, "[LOLog] 가입 인증번호", """
				LOLog 가입 인증번호는 %s 이에요.
				10분 안에 앱에 입력해 주세요.

				직접 요청하지 않았다면 이 메일은 무시해 주세요.
				""".formatted(code));
	}

	@Override
	public void sendAlreadyRegistered(String email) {
		send(email, "[LOLog] 이미 가입된 계정이에요", """
				이 이메일로 가입된 LOLog 계정이 이미 있어요.
				처음 가입한 방법(이메일 또는 구글·네이버)으로 로그인해 주세요.

				직접 요청하지 않았다면 이 메일은 무시해 주세요.
				""");
	}

	@Override
	public void sendPasswordResetCode(String email, String code) {
		send(email, "[LOLog] 비밀번호 찾기 인증번호", """
				LOLog 비밀번호 찾기 인증번호는 %s 이에요.
				10분 안에 앱에 입력하고 새 비밀번호를 정해 주세요.

				직접 요청하지 않았다면 이 메일은 무시해 주세요. 비밀번호는 바뀌지 않아요.
				""".formatted(code));
	}

	@Override
	public void sendPasswordResetSocialOnly(String email) {
		send(email, "[LOLog] 소셜 로그인으로 가입한 계정이에요", """
				이 이메일의 LOLog 계정은 구글 또는 네이버로 가입해서 비밀번호가 없어요.
				가입한 방법(구글·네이버)으로 로그인해 주세요.

				직접 요청하지 않았다면 이 메일은 무시해 주세요.
				""");
	}

	private void send(String to, String subject, String text) {
		SimpleMailMessage message = new SimpleMailMessage();
		message.setFrom(from);
		message.setTo(to);
		message.setSubject(subject);
		message.setText(text);
		sender.send(message);
	}

}
