package com.lolog.auth.common;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

// 지금 시각. 테스트에서 토큰 만료를 시험할 수 있게 빈으로 둔다.
@Configuration(proxyBeanMethods = false)
public class TimeConfig {

	@Bean
	Clock clock() {
		return Clock.systemDefaultZone();
	}

}
