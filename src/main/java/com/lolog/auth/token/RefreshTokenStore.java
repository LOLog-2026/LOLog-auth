package com.lolog.auth.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;
import java.util.Set;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

// 리프레시 토큰을 Redis에 둔다(api-spec.md 인증 서비스).
// 토큰은 JWT가 아닌 무작위 문자열이고 14일 동안 쓴다. Redis에는 원래 값이 아니라 SHA-256 해시만 키로 둔다.
//
// lolog:auth:refresh:{해시}        → "{userId}:{만료 시각(초)}"
// lolog:auth:user-refresh:{userId} → 그 회원의 토큰 해시 집합 (탈퇴 때 모두 지우려고, #3)
//
// 만료된 토큰에 INVALID_TOKEN이 아니라 TOKEN_EXPIRED로 답하려고, 키는 만료 뒤에도 하루 더 남겨 둔다.
@Component
public class RefreshTokenStore {

	public static final Duration VALIDITY = Duration.ofDays(14);

	// 만료 뒤에도 키를 남겨 두는 시간. 이 시간이 지나면 TOKEN_EXPIRED 대신 INVALID_TOKEN이 된다.
	static final Duration EXPIRED_KEEP = Duration.ofDays(1);

	private static final String TOKEN_KEY = "lolog:auth:refresh:";

	private static final String USER_KEY = "lolog:auth:user-refresh:";

	private static final int TOKEN_BYTES = 32;

	private final SecureRandom random = new SecureRandom();

	private final StringRedisTemplate redis;

	private final Clock clock;

	public RefreshTokenStore(StringRedisTemplate redis, Clock clock) {
		this.redis = redis;
		this.clock = clock;
	}

	// 새 리프레시 토큰을 만들어 저장하고 원래 값을 돌려준다.
	public String issue(long userId) {
		byte[] bytes = new byte[TOKEN_BYTES];
		random.nextBytes(bytes);
		String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
		String hash = hash(token);
		long expiresAt = clock.instant().plus(VALIDITY).getEpochSecond();
		Duration ttl = VALIDITY.plus(EXPIRED_KEEP);

		redis.opsForValue().set(TOKEN_KEY + hash, userId + ":" + expiresAt, ttl);
		redis.opsForSet().add(USER_KEY + userId, hash);
		redis.expire(USER_KEY + userId, ttl);
		return token;
	}

	// 토큰을 꺼내면서 지운다. 갱신 때 옛 토큰을 다시 못 쓰게 하려는 것이고, 꺼내기와 지우기가 한 번에 일어나므로
	// 같은 토큰으로 두 요청이 동시에 와도 하나만 성공한다.
	public Optional<Entry> take(String token) {
		String hash = hash(token);
		String value = redis.opsForValue().getAndDelete(TOKEN_KEY + hash);
		if (value == null) {
			return Optional.empty();
		}
		int colon = value.indexOf(':');
		long userId = Long.parseLong(value.substring(0, colon));
		Instant expiresAt = Instant.ofEpochSecond(Long.parseLong(value.substring(colon + 1)));
		redis.opsForSet().remove(USER_KEY + userId, hash);
		return Optional.of(new Entry(userId, !clock.instant().isBefore(expiresAt)));
	}

	// 토큰을 무효로 한다. 없는 토큰이어도 그냥 넘어간다.
	public void revoke(String token) {
		take(token);
	}

	// 그 회원의 리프레시 토큰을 모두 지운다(탈퇴, FR-AUTH-05).
	public void revokeAll(long userId) {
		Set<String> hashes = redis.opsForSet().members(USER_KEY + userId);
		if (hashes != null && !hashes.isEmpty()) {
			redis.delete(hashes.stream().map(hash -> TOKEN_KEY + hash).toList());
		}
		redis.delete(USER_KEY + userId);
	}

		static String hash(String token) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(digest);
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	// 꺼낸 토큰의 주인과 만료 여부
	public record Entry(long userId, boolean expired) {
	}

}
