package com.lolog.auth.token;

import java.time.Clock;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

// 정지된 회원 ID를 Redis에 잠시 남겨 둔다(LOLog-docs PR #59 spec/admin.md 2장).
// 정지 전에 받은 액세스 토큰을 탈퇴와 같은 방법으로 막는다. lolog-api는 요청마다 탈퇴 키와 함께 이 키를 본다.
//
// lolog:auth:suspended:{userId} → 정지 시각(초)
//
// 정지하면 리프레시 토큰을 모두 지우고 로그인·갱신도 막으므로, 새 액세스 토큰은 생기지 않는다.
// 그래서 키는 정지 전에 받은 액세스 토큰이 만료될 때까지(탈퇴 키와 같은 31분)만 두면 된다. 정지를 풀면 지운다.
@Component
public class SuspendedUsers {

	public static final String KEY = "lolog:auth:suspended:";

	private final StringRedisTemplate redis;

	private final Clock clock;

	public SuspendedUsers(StringRedisTemplate redis, Clock clock) {
		this.redis = redis;
		this.clock = clock;
	}

	public void add(long userId) {
		redis.opsForValue().set(KEY + userId, Long.toString(clock.instant().getEpochSecond()), WithdrawnUsers.TTL);
	}

	public void remove(long userId) {
		redis.delete(KEY + userId);
	}

	public boolean contains(long userId) {
		return Boolean.TRUE.equals(redis.hasKey(KEY + userId));
	}

}
