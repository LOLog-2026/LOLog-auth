package com.lolog.auth;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

// 테스트에서 시각을 앞으로 돌릴 수 있는 시계. @Import(MutableClock.Config.class)로 붙이면 서버의 Clock을 대신한다.
public class MutableClock extends Clock {

	// JWT 시각은 초 단위라, 경계 시험이 밀리초 때문에 어긋나지 않게 초로 맞춘다.
	private volatile Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);

	public void reset() {
		now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
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
