package com.lolog.auth.admin;

import com.lolog.auth.common.ApiException;
import com.lolog.auth.token.RefreshTokenStore;
import com.lolog.auth.token.SuspendedUsers;
import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import java.time.Clock;
import java.time.OffsetDateTime;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

// 관리자가 계정을 정지하고 푼다(LOLog-docs PR #59 spec/admin.md 2장, FR-ADMIN-02).
// lolog-api에 알리는 일은 SuspensionNotifier가 맡는다(트랜잭션이 끝난 뒤 컨트롤러가 부른다).
@Service
public class AdminSuspensionService {

	static final int REASON_MAX = 200;

	private final UserRepository users;

	private final RefreshTokenStore refreshTokens;

	private final SuspendedUsers suspendedUsers;

	private final Clock clock;

	public AdminSuspensionService(UserRepository users, RefreshTokenStore refreshTokens,
			SuspendedUsers suspendedUsers, Clock clock) {
		this.users = users;
		this.refreshTokens = refreshTokens;
		this.suspendedUsers = suspendedUsers;
		this.clock = clock;
	}

	// 정지한다. 이미 정지 중이면 새 기한·이유로 바꾼다. 기한은 지금부터 잰다.
	// 그 회원의 리프레시 토큰을 모두 지우고, 남은 액세스 토큰은 SuspendedUsers 키로 막는다.
	// Redis 쓰기가 실패하면 예외로 DB 변경도 되돌려, 토큰이 살아 있는 채로 정지되지 않게 한다.
	@Transactional
	public void suspend(long targetId, String durationValue, String reasonValue) {
		Duration duration = Duration.parse(durationValue);
		String reason = reason(reasonValue);
		User target = target(targetId);
		OffsetDateTime now = OffsetDateTime.now(clock);
		target.suspend(now, duration.until(now), reason);
		suspendedUsers.add(targetId);
		refreshTokens.revokeAll(targetId);
	}

	// 정지를 푼다. 정지 중이 아니어도 204다(정지 기록이 없으면 lolog-api에도 알리지 않는다).
	// 기한이 지나 저절로 풀린 기록도 지운다.
	@Transactional
	public void unsuspend(long targetId) {
		User target = target(targetId);
		if (target.unsuspend()) {
			suspendedUsers.remove(targetId);
		}
	}

	// 살아 있는 회원을 잠가 찾는다. 없거나 탈퇴했으면 404, 관리자(나 포함)면 403이다.
	private User target(long targetId) {
		User target = users.lockActive(targetId)
			.orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "USER_NOT_FOUND", "회원이 없습니다."));
		if (target.isAdmin()) {
			throw new ApiException(HttpStatus.FORBIDDEN, "FORBIDDEN", "관리자는 정지할 수 없습니다.");
		}
		return target;
	}

	// 이유는 앞뒤 공백을 빼고 1~200자다.
	private static String reason(String value) {
		String reason = value == null ? "" : value.strip();
		if (reason.isEmpty() || reason.codePointCount(0, reason.length()) > REASON_MAX) {
			throw ApiException.invalid("reason", "reason은 1~200자여야 합니다.");
		}
		return reason;
	}

	// 정지 기한(이름은 초안). PERMANENT는 기한이 없다(suspended_until NULL).
	enum Duration {

		MONTH_1(1), MONTH_3(3), MONTH_6(6), PERMANENT(0);

		private final int months;

		Duration(int months) {
			this.months = months;
		}

		static Duration parse(String value) {
			for (Duration duration : values()) {
				if (duration.name().equals(value)) {
					return duration;
				}
			}
			throw ApiException.invalid("duration", "duration은 MONTH_1, MONTH_3, MONTH_6, PERMANENT 중 하나여야 합니다.");
		}

		OffsetDateTime until(OffsetDateTime now) {
			return this == PERMANENT ? null : now.plusMonths(months);
		}

	}

}
