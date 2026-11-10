package com.lolog.auth;

import com.lolog.auth.email.VerificationMailer;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

// 테스트용 메일 발송기. 보낸 메일을 기억하고, fail을 켜면 보내기에 실패한다.
// TestContainers가 함께 불러오므로 모든 통합 테스트에서 실제 메일을 보내지 않는다.
public class FakeMailer implements VerificationMailer {

	public final List<Mail> sent = new CopyOnWriteArrayList<>();

	public final AtomicBoolean fail = new AtomicBoolean();

	@Override
	public void sendCode(String email, String code) {
		send(new Mail(email, code));
	}

	@Override
	public void sendAlreadyRegistered(String email) {
		send(new Mail(email, null));
	}

	private void send(Mail mail) {
		if (fail.get()) {
			throw new org.springframework.mail.MailSendException("테스트용 실패");
		}
		sent.add(mail);
	}

	// 그 이메일로 마지막에 보낸 메일
	public Mail last(String email) {
		return sent.stream().filter(m -> m.to().equals(email)).reduce((a, b) -> b).orElseThrow();
	}

	public long count(String email) {
		return sent.stream().filter(m -> m.to().equals(email)).count();
	}

	// code가 null이면 "이미 가입된 계정" 안내 메일이다.
	public record Mail(String to, String code) {
	}

	@TestConfiguration(proxyBeanMethods = false)
	public static class Config {

		@Bean
		@Primary
		FakeMailer fakeMailer() {
			return new FakeMailer();
		}

	}

}
