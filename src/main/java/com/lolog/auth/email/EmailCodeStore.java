package com.lolog.auth.email;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

// 메일 인증번호를 Redis에 둔다(api-spec.md "가입 인증번호", "비밀번호 찾기 인증번호").
// 키에는 이메일 원문 대신 SHA-256 해시를 쓰고, 번호도 해시로만 둔다. 용도(Purpose)마다 키를 나눠 서로 바꿔 쓸 수 없다.
//
// lolog:auth:{용도}:{이메일 해시}          → 해시 { code: 번호 해시, tries: 틀린 횟수, exp: 만료 시각(초) }
// lolog:auth:{용도}-cooldown:{이메일 해시} → 다시 보낼 수 있는 시각(초)
// 용도: email-code(가입), password-reset-code(비밀번호 찾기)
//
// 만료와 다시 보내기 간격은 Redis TTL이 아니라 저장한 시각과 Clock으로 판단한다(테스트에서 시각을 돌릴 수 있게).
// TTL은 키가 쌓이지 않게 지우는 용도로만, 판단 시간보다 넉넉하게 둔다.
@Component
public class EmailCodeStore {

	public static final Duration VALIDITY = Duration.ofMinutes(10);

	public static final Duration COOLDOWN = Duration.ofSeconds(60);

	public static final int MAX_TRIES = 5;

	private static final Duration KEEP_EXTRA = Duration.ofMinutes(1);


	// 다시 보낼 수 있으면 다음 시각을 적고 1, 아직 간격 안이면 0.
	private static final RedisScript<Long> TAKE_COOLDOWN = RedisScript.of("""
			local next = redis.call('GET', KEYS[1])
			if next and tonumber(next) > tonumber(ARGV[1]) then return 0 end
			redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
			return 1
			""", Long.class);

	// 전 번호를 지우고 새 번호를 둔다.
	private static final RedisScript<Long> SAVE = RedisScript.of("""
			redis.call('DEL', KEYS[1])
			redis.call('HSET', KEYS[1], 'code', ARGV[1], 'tries', 0, 'exp', ARGV[2])
			redis.call('EXPIRE', KEYS[1], ARGV[3])
			return 1
			""", Long.class);

	// 1: 맞음(번호를 지움), 0: 틀림, -1: 없음·만료·횟수 초과.
	// 횟수를 먼저 올리고 비교하므로 같은 번호로 동시에 여러 번 와도 MAX_TRIES번까지만 비교한다.
	private static final RedisScript<Long> CHECK = RedisScript.of("""
			local code = redis.call('HGET', KEYS[1], 'code')
			if not code then return -1 end
			if tonumber(redis.call('HGET', KEYS[1], 'exp')) <= tonumber(ARGV[2]) then
			  redis.call('DEL', KEYS[1])
			  return -1
			end
			local tries = redis.call('HINCRBY', KEYS[1], 'tries', 1)
			if tries > tonumber(ARGV[3]) then
			  redis.call('DEL', KEYS[1])
			  return -1
			end
			if code == ARGV[1] then
			  redis.call('DEL', KEYS[1])
			  return 1
			end
			if tries >= tonumber(ARGV[3]) then redis.call('DEL', KEYS[1]) end
			return 0
			""", Long.class);

	private final StringRedisTemplate redis;

	private final Clock clock;

	public EmailCodeStore(StringRedisTemplate redis, Clock clock) {
		this.redis = redis;
		this.clock = clock;
	}

	// 가입 인증번호용. 아래 Purpose를 받는 메서드에 SIGNUP을 넘긴 것과 같다.
	public boolean tryStartCooldown(String email) {
		return tryStartCooldown(Purpose.SIGNUP, email);
	}

	public void clearCooldown(String email) {
		clearCooldown(Purpose.SIGNUP, email);
	}

	public void save(String email, String code) {
		save(Purpose.SIGNUP, email, code);
	}

	public void delete(String email) {
		delete(Purpose.SIGNUP, email);
	}

	public Result check(String email, String code) {
		return check(Purpose.SIGNUP, email, code);
	}

	// 60초 간격을 지켰으면 true. 이메일은 소문자로 바꾼 값이어야 한다.
	public boolean tryStartCooldown(Purpose purpose, String email) {
		long now = clock.instant().getEpochSecond();
		Long result = redis.execute(TAKE_COOLDOWN, List.of(purpose.cooldownKey(email)), Long.toString(now),
				Long.toString(now + COOLDOWN.toSeconds()), Long.toString(COOLDOWN.plus(KEEP_EXTRA).toSeconds()));
		return result != null && result == 1;
	}

	// 메일을 보내지 못했을 때 바로 다시 받을 수 있게 간격을 푼다.
	public void clearCooldown(Purpose purpose, String email) {
		redis.delete(purpose.cooldownKey(email));
	}

	public void save(Purpose purpose, String email, String code) {
		long exp = clock.instant().plus(VALIDITY).getEpochSecond();
		redis.execute(SAVE, List.of(purpose.codeKey(email)), hash(code), Long.toString(exp),
				Long.toString(VALIDITY.plus(KEEP_EXTRA).toSeconds()));
	}

	public void delete(Purpose purpose, String email) {
		redis.delete(purpose.codeKey(email));
	}

	public Result check(Purpose purpose, String email, String code) {
		Long result = redis.execute(CHECK, List.of(purpose.codeKey(email)), hash(code),
				Long.toString(clock.instant().getEpochSecond()), Integer.toString(MAX_TRIES));
		if (result == null || result < 0) {
			return Result.EXPIRED;
		}
		return result == 1 ? Result.MATCHED : Result.WRONG;
	}

	static String hash(String value) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(digest);
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	// 인증번호 용도. 키 이름이 lolog-api와 겹치지 않게 lolog:auth:로 시작한다.
	public enum Purpose {

		SIGNUP("email-code"), PASSWORD_RESET("password-reset-code");

		private final String name;

		Purpose(String name) {
			this.name = name;
		}

		String codeKey(String email) {
			return "lolog:auth:" + name + ":" + hash(email);
		}

		String cooldownKey(String email) {
			return "lolog:auth:" + name + "-cooldown:" + hash(email);
		}

	}

	public enum Result {

		MATCHED, WRONG, EXPIRED

	}

}
