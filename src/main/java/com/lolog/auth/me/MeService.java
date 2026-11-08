package com.lolog.auth.me;

import com.lolog.auth.common.ApiException;
import com.lolog.auth.token.RefreshTokenStore;
import com.lolog.auth.token.WithdrawnUsers;
import com.lolog.auth.user.SocialAccount;
import com.lolog.auth.user.SocialAccountRepository;
import com.lolog.auth.user.SocialProvider;
import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

// 내 정보 보기와 탈퇴(FR-AUTH-05, FR-AUTH-06).
@Service
public class MeService {

	private final UserRepository users;

	private final SocialAccountRepository socialAccounts;

	private final RefreshTokenStore refreshTokens;

	private final WithdrawnUsers withdrawnUsers;

	private final Clock clock;

	public MeService(UserRepository users, SocialAccountRepository socialAccounts, RefreshTokenStore refreshTokens,
			WithdrawnUsers withdrawnUsers, Clock clock) {
		this.users = users;
		this.socialAccounts = socialAccounts;
		this.refreshTokens = refreshTokens;
		this.withdrawnUsers = withdrawnUsers;
		this.clock = clock;
	}

	@Transactional(readOnly = true)
	public MeResponse me(long userId) {
		User user = activeUser(userId);
		return new MeResponse(user.getEmail(), linkedProviders(userId));
	}

	// 회원과 소셜 연결을 소프트 삭제하고 리프레시 토큰을 모두 지운다. 남은 액세스 토큰은 WithdrawnUsers로 막는다.
	// Redis 쓰기가 실패하면 예외로 DB 삭제도 되돌려, 토큰이 살아 있는 채로 탈퇴되지 않게 한다.
	// lolog-api 데이터 삭제는 UserDataDeleter가 맡는다.
	@Transactional
	public void withdraw(long userId) {
		User user = activeUser(userId);
		OffsetDateTime now = OffsetDateTime.now(clock);
		user.delete(now);
		socialAccounts.findByUserIdAndDeletedAtIsNull(userId).forEach(account -> account.delete(now));
		withdrawnUsers.add(userId);
		refreshTokens.revokeAll(userId);
	}

	// 연결된 회사. 순서는 KAKAO, GOOGLE, NAVER로 고정한다.
	List<String> linkedProviders(long userId) {
		return socialAccounts.findByUserIdAndDeletedAtIsNull(userId)
			.stream()
			.map(SocialAccount::getProvider)
			.sorted()
			.map(SocialProvider::name)
			.toList();
	}

	// 토큰은 맞지만 탈퇴했거나 없는 회원이면 401 INVALID_TOKEN이다. 탈퇴한 회원의 액세스 토큰은 30분 동안 서명이 맞다.
	private User activeUser(long userId) {
		return users.findByIdAndDeletedAtIsNull(userId)
			.orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_TOKEN", "회원이 없습니다."));
	}

	// MeResponse (api-dto.md 1장)
	public record MeResponse(String email, List<String> linkedProviders) {
	}

}
