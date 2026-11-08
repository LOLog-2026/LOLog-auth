package com.lolog.auth.token;

import java.time.Clock;
import java.time.Duration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

// 탈퇴한 회원 ID를 Redis에 잠시 남겨 둔다(api-spec.md "탈퇴한 회원의 토큰").
// 액세스 토큰은 서버에 저장하지 않아 지울 수 없으므로, 탈퇴 전에 받은 토큰이 만료될 때까지 lolog-api가 이 키를 보고 막는다.
//
// lolog:auth:withdrawn:{userId} → 탈퇴 시각(초)
//
// 사용자 ID는 다시 쓰지 않으므로(BIGSERIAL) 키가 있으면 그 회원의 액세스 토큰은 모두 무효다.
@Component
public class WithdrawnUsers {

	// 31분. 액세스 토큰 유효 시간 30분 + lolog-api의 시계 오차 허용 30초에, 경계에서 놓치지 않게 30초를 더한다.
	public static final Duration TTL = AccessTokenIssuer.VALIDITY.plus(AccessTokenVerifier.CLOCK_SKEW)
		.plusSeconds(30);

	public static final String KEY = "lolog:auth:withdrawn:";

	private final StringRedisTemplate redis;

	private final Clock clock;

	public WithdrawnUsers(StringRedisTemplate redis, Clock clock) {
		this.redis = redis;
		this.clock = clock;
	}

	public void add(long userId) {
		redis.opsForValue().set(KEY + userId, Long.toString(clock.instant().getEpochSecond()), TTL);
	}

}
