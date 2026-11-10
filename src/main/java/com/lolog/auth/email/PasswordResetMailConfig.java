package com.lolog.auth.email;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

// 비밀번호 찾기 메일은 204로 답한 뒤 이 실행기에서 보낸다. 가입 여부가 응답 시간으로 드러나지 않게 하려고서다.
// 한꺼번에 몰려도 메모리를 다 쓰지 않게 대기열을 막아 두고, 꽉 차면 요청을 500으로 돌려보낸다(PasswordService).
@Configuration(proxyBeanMethods = false)
public class PasswordResetMailConfig {

	public static final String EXECUTOR = "passwordResetMailExecutor";

	@Bean(EXECUTOR)
	ThreadPoolTaskExecutor passwordResetMailExecutor() {
		ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
		executor.setCorePoolSize(2);
		executor.setMaxPoolSize(2);
		executor.setQueueCapacity(100);
		executor.setThreadNamePrefix("password-reset-mail-");
		// 서버를 끌 때 보내던 메일은 마저 보낸다.
		executor.setWaitForTasksToCompleteOnShutdown(true);
		executor.setAwaitTerminationSeconds(15);
		return executor;
	}

}
