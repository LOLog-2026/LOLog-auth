package com.lolog.auth.token;

import com.lolog.auth.common.ApiException;
import com.lolog.auth.user.Role;
import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

// 토큰 한 벌(액세스 + 리프레시)을 발급하고, 갱신·로그아웃을 처리한다(FR-AUTH-03, FR-AUTH-04).
@Service
public class TokenService {

	private final AccessTokenIssuer accessTokens;

	private final RefreshTokenStore refreshTokens;

	private final UserRepository users;

	public TokenService(AccessTokenIssuer accessTokens, RefreshTokenStore refreshTokens, UserRepository users) {
		this.accessTokens = accessTokens;
		this.refreshTokens = refreshTokens;
		this.users = users;
	}

	// 액세스 토큰의 role은 발급할 때 DB에서 읽는다. 관리자에서 빼도 이미 준 토큰은 만료(30분)까지 그대로다.
	public TokenResponse issue(long userId) {
		Role role = users.findById(userId).map(User::getRole).orElse(Role.USER);
		return new TokenResponse(accessTokens.issue(userId, role), refreshTokens.issue(userId),
				(int) AccessTokenIssuer.VALIDITY.toSeconds());
	}

	// 옛 리프레시 토큰은 지우고 새 한 벌을 준다. 만료면 TOKEN_EXPIRED, 없거나 이미 쓴 값이면 INVALID_TOKEN.
	public TokenResponse refresh(String refreshToken) {
		RefreshTokenStore.Entry entry = refreshTokens.take(refreshToken).orElseThrow(TokenService::invalidToken);
		if (entry.expired()) {
			throw new ApiException(HttpStatus.UNAUTHORIZED, "TOKEN_EXPIRED", "리프레시 토큰이 만료됐습니다.");
		}
		// 탈퇴한 회원의 토큰은 탈퇴 때 지우지만(#3), 혹시 남아 있어도 새 토큰을 주지 않는다.
		if (users.findByIdAndDeletedAtIsNull(entry.userId()).isEmpty()) {
			throw invalidToken();
		}
		return issue(entry.userId());
	}

	// 리프레시 토큰을 무효로 한다. 없거나 만료된 값이어도 204로 답한다(이미 로그아웃된 것과 같다).
	public void logout(String refreshToken) {
		refreshTokens.revoke(refreshToken);
	}

	private static ApiException invalidToken() {
		return new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_TOKEN", "리프레시 토큰이 올바르지 않습니다.");
	}

}
