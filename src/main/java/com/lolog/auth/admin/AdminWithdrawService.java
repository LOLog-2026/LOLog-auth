package com.lolog.auth.admin;

import com.lolog.auth.common.ApiException;
import com.lolog.auth.me.MeService;
import com.lolog.auth.user.BannedIdentity;
import com.lolog.auth.user.BannedIdentityRepository;
import com.lolog.auth.user.SocialAccount;
import com.lolog.auth.user.SocialAccountRepository;
import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import java.time.Clock;
import java.time.OffsetDateTime;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

// 관리자가 계정을 탈퇴시킨다(LOLog-docs PR #59 spec/admin.md 3장, FR-ADMIN-04).
// 본인 탈퇴와 같은 처리를 하고, 그 계정의 이메일과 연결된 소셜 계정을 적어 두어 다시 가입하지 못하게 한다.
// lolog-api 데이터 삭제는 UserDataDeleter가 맡는다(트랜잭션이 끝난 뒤 컨트롤러가 부른다).
@Service
public class AdminWithdrawService {

	private final UserRepository users;

	private final SocialAccountRepository socialAccounts;

	private final BannedIdentityRepository bannedIdentities;

	private final MeService me;

	private final Clock clock;

	public AdminWithdrawService(UserRepository users, SocialAccountRepository socialAccounts,
			BannedIdentityRepository bannedIdentities, MeService me, Clock clock) {
		this.users = users;
		this.socialAccounts = socialAccounts;
		this.bannedIdentities = bannedIdentities;
		this.me = me;
		this.clock = clock;
	}

	// 없거나 이미 탈퇴한 회원이면 404, 관리자(나 포함)면 403이다.
	// 소셜 연결은 탈퇴 처리에서 지워지므로 그 전에 적는다. Redis 쓰기가 실패하면 예외로 모두 되돌린다.
	@Transactional
	public void withdraw(long targetId) {
		User target = users.lockActive(targetId)
			.orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "USER_NOT_FOUND", "회원이 없습니다."));
		if (target.isAdmin()) {
			throw new ApiException(HttpStatus.FORBIDDEN, "FORBIDDEN", "관리자는 탈퇴시킬 수 없습니다.");
		}
		OffsetDateTime now = OffsetDateTime.now(clock);
		ban(BannedIdentity.Kind.EMAIL, target.getEmail(), targetId, now);
		for (SocialAccount account : socialAccounts.findByUserIdAndDeletedAtIsNull(targetId)) {
			ban(BannedIdentity.Kind.of(account.getProvider()), account.getProviderUserId(), targetId, now);
		}
		me.withdrawUser(target);
	}

	// 이미 적혀 있으면 넘어간다(같은 값은 한 줄만, uk_banned_identities_kind_value).
	private void ban(BannedIdentity.Kind kind, String value, long userId, OffsetDateTime now) {
		if (!bannedIdentities.existsByKindAndValue(kind, value)) {
			bannedIdentities.save(new BannedIdentity(kind, value, userId, now));
		}
	}

}
