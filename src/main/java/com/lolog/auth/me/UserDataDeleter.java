package com.lolog.auth.me;

import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import java.time.Clock;
import java.time.OffsetDateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

// 탈퇴한 회원의 데이터를 lolog-api가 다 지울 때까지(204) 다시 부른다(LOLog-docs PR #28).
// 탈퇴 요청 안에서 한 번 부르고, 실패하면 남겨 두었다가 주기마다 다시 부른다. 서버가 다시 떠도 DB에 남아 있어 이어서 부른다.
@Component
public class UserDataDeleter {

	private static final Logger log = LoggerFactory.getLogger(UserDataDeleter.class);

	private final UserRepository users;

	private final UserDataClient client;

	private final TransactionTemplate tx;

	private final Clock clock;

	public UserDataDeleter(UserRepository users, UserDataClient client, TransactionTemplate tx, Clock clock) {
		this.users = users;
		this.client = client;
		this.tx = tx;
		this.clock = clock;
	}

	// 204를 받으면 끝났다고 적는다. 실패해도 예외를 내지 않는다(다음 주기에 다시 부른다).
	public boolean tryDelete(long userId) {
		if (!client.deleteUserData(userId)) {
			log.warn("lolog-api 회원 데이터 삭제 실패, 다시 부릅니다. userId={}", userId);
			return false;
		}
		tx.executeWithoutResult(status -> users.findById(userId)
			.ifPresent(user -> user.markDataDeleted(OffsetDateTime.now(clock))));
		return true;
	}

	@Scheduled(fixedDelayString = "${lolog.user-data-delete.retry-delay:PT1M}",
			initialDelayString = "${lolog.user-data-delete.retry-delay:PT1M}")
	public void retryPending() {
		for (User user : users.findByDeletedAtIsNotNullAndDataDeletedAtIsNull()) {
			tryDelete(user.getId());
		}
	}

}
