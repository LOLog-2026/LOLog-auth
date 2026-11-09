package com.lolog.auth.social;

import com.lolog.auth.common.ApiException;
import com.lolog.auth.me.MeService;
import com.lolog.auth.token.TokenResponse;
import com.lolog.auth.token.TokenService;
import com.lolog.auth.user.SocialAccount;
import com.lolog.auth.user.SocialAccountRepository;
import com.lolog.auth.user.SocialProvider;
import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

// 소셜 로그인(FR-AUTH-02)과 내 계정에 소셜 계정 연결(FR-AUTH-06). 계정 합치기는 없다.
// 회사에 토큰을 확인하는 동안 DB 트랜잭션을 열어 두지 않으려고, DB 작업만 TransactionTemplate으로 묶는다.
@Service
public class SocialAuthService {

	private static final int EMAIL_MAX = 254;

	private final GoogleIdTokenVerifier google;

	private final NaverTokenVerifier naver;

	private final UserRepository users;

	private final SocialAccountRepository socialAccounts;

	private final TokenService tokens;

	private final MeService me;

	private final TransactionTemplate tx;

	private final Clock clock;

	public SocialAuthService(GoogleIdTokenVerifier google, NaverTokenVerifier naver, UserRepository users,
			SocialAccountRepository socialAccounts, TokenService tokens, MeService me, TransactionTemplate tx,
			Clock clock) {
		this.google = google;
		this.naver = naver;
		this.users = users;
		this.socialAccounts = socialAccounts;
		this.tokens = tokens;
		this.me = me;
		this.tx = tx;
		this.clock = clock;
	}

	// 연결된 소셜 계정이면 그 회원으로 로그인한다. 처음이면 가입도 같이 한다.
	// 그 이메일로 살아 있는 계정이 이미 있으면 409 ACCOUNT_EXISTS(계정 합치기 없음).
	// 회사가 토큰을 확인해 주지 않거나, 이메일을 주지 않았거나 인증 안 된 이메일이면 401 INVALID_TOKEN이다.
	public Result login(SocialProvider provider, String providerToken) {
		SocialProfile profile = verify(provider, providerToken);
		Optional<Long> linked = linkedUserId(provider, profile.providerUserId());
		if (linked.isPresent()) {
			return new Result(tokens.issue(linked.get()), false);
		}
		String email = usableEmail(profile.email());
		long userId;
		try {
			userId = tx.execute(status -> {
				if (users.existsByEmailAndDeletedAtIsNull(email)) {
					throw new ApiException(HttpStatus.CONFLICT, "ACCOUNT_EXISTS", "이미 가입된 이메일입니다.");
				}
				OffsetDateTime now = OffsetDateTime.now(clock);
				User user = users.saveAndFlush(User.social(email, now));
				socialAccounts.saveAndFlush(new SocialAccount(user.getId(), provider, profile.providerUserId(), now));
				return user.getId();
			});
		}
		catch (DataIntegrityViolationException e) {
			// 같은 소셜 계정으로 동시에 처음 로그인했으면 먼저 만든 계정으로 로그인한다.
			// 같은 이메일로 다른 가입이 동시에 끝났으면 409다.
			userId = linkedUserId(provider, profile.providerUserId())
				.orElseThrow(() -> new ApiException(HttpStatus.CONFLICT, "ACCOUNT_EXISTS", "이미 가입된 이메일입니다."));
			return new Result(tokens.issue(userId), false);
		}
		return new Result(tokens.issue(userId), true);
	}

	// 로그인한 회원에 소셜 계정을 붙인다. 이미 내 계정에 붙어 있으면 그대로 200이다.
	// 그 소셜 계정이 다른 계정에 붙어 있거나, 내 계정에 같은 회사의 다른 계정이 붙어 있으면 409 SOCIAL_ALREADY_LINKED.
	// 연결에는 이메일을 쓰지 않으므로 회사가 이메일을 주지 않아도 된다.
	public List<String> link(long userId, SocialProvider provider, String providerToken) {
		if (users.findByIdAndDeletedAtIsNull(userId).isEmpty()) {
			throw new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_TOKEN", "회원이 없습니다.");
		}
		SocialProfile profile = verify(provider, providerToken);
		try {
			tx.executeWithoutResult(status -> {
				Optional<SocialAccount> existing = socialAccounts
					.findByProviderAndProviderUserIdAndDeletedAtIsNull(provider, profile.providerUserId());
				if (existing.isPresent()) {
					if (existing.get().getUserId() != userId) {
						throw alreadyLinked();
					}
					return;
				}
				boolean sameProviderLinked = socialAccounts.findByUserIdAndDeletedAtIsNull(userId)
					.stream()
					.anyMatch(account -> account.getProvider() == provider);
				if (sameProviderLinked) {
					throw alreadyLinked();
				}
				socialAccounts.saveAndFlush(
						new SocialAccount(userId, provider, profile.providerUserId(), OffsetDateTime.now(clock)));
			});
		}
		catch (DataIntegrityViolationException e) {
			// 동시에 같은 연결을 두 번 보냈으면 이미 붙은 것이라 200이다. 그 밖에는 409다.
			if (!linkedUserId(provider, profile.providerUserId()).map(id -> id == userId).orElse(false)) {
				throw alreadyLinked();
			}
		}
		return me.linkedProviders(userId);
	}

	private SocialProfile verify(SocialProvider provider, String providerToken) {
		try {
			return switch (provider) {
				case GOOGLE -> google.verify(providerToken);
				case NAVER -> naver.verify(providerToken);
			};
		}
		catch (InvalidProviderTokenException e) {
			throw invalidToken();
		}
	}

	private Optional<Long> linkedUserId(SocialProvider provider, String providerUserId) {
		return socialAccounts.findByProviderAndProviderUserIdAndDeletedAtIsNull(provider, providerUserId)
			.map(SocialAccount::getUserId);
	}

	// 가입에 쓸 이메일. 없거나 형식이 맞지 않으면 회사가 확인해 주지 않은 것과 같게 401이다.
	private static String usableEmail(String email) {
		if (email == null || email.isBlank()) {
			throw invalidToken();
		}
		String normalized = User.normalizeEmail(email);
		if (normalized.length() > EMAIL_MAX || !normalized.contains("@")) {
			throw invalidToken();
		}
		return normalized;
	}

	private static ApiException invalidToken() {
		return new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_TOKEN", "소셜 계정을 확인하지 못했습니다.");
	}

	private static ApiException alreadyLinked() {
		return new ApiException(HttpStatus.CONFLICT, "SOCIAL_ALREADY_LINKED", "이미 연결된 소셜 계정입니다.");
	}

	public record Result(TokenResponse tokens, boolean newUser) {
	}

}
