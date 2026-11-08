package com.lolog.auth;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

// 테스트에서 시각을 앞으로 돌릴 수 있는 시계. @Import(MutableClock.Config.class)로 붙이면 서버의 Clock을 대신한다.
public class MutableClock extends Clock {

	private volatile Instant now = Instant.now();

	public void reset() {
		now = Instant.now();
	}

	public void advance(Duration duration) {
		now = now.plus(duration);
	}

	@Override
	public Instant instant() {
		return now;
	}

	@Override
	public ZoneId getZone() {
		return ZoneOffset.UTC;
	}

	@Override
	public Clock withZone(ZoneId zone) {
		return this;
	}

	@TestConfiguration(proxyBeanMethods = false)
	public static class Config {

		@Bean
		@Primary
		MutableClock testClock() {
			return new MutableClock();
		}

	}

}
