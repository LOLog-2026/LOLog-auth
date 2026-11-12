package com.lolog.auth.admin;

import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import java.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

// 정지·해제를 lolog-api가 받을 때까지(204) 다시 부른다. 탈퇴 데이터 삭제(UserDataDeleter)와 같은 방식이다.
// 정지·해제 요청 안에서 한 번 부르고, 실패하면 users.suspension_notify_pending을 남겨 두었다가 주기마다 다시 부른다.
// 매번 지금 DB의 상태를 알리므로, 정지 뒤 바로 풀었으면 마지막 상태(해제)만 알려도 된다.
@Component
public class SuspensionNotifier {

	private static final Logger log = LoggerFactory.getLogger(SuspensionNotifier.class);

	private final UserRepository users;

	private final SuspensionClient client;

	private final TransactionTemplate tx;

	private final Clock clock;

	public SuspensionNotifier(UserRepository users, SuspensionClient client, TransactionTemplate tx, Clock clock) {
		this.users = users;
		this.client = client;
		this.tx = tx;
		this.clock = clock;
	}

	// 204를 받으면 대기를 끝낸다. 실패해도 예외를 내지 않는다(다음 주기에 다시 부른다).
	public boolean tryNotify(long userId) {
		User user = users.findById(userId).orElse(null);
		if (user == null || !user.isSuspensionNotifyPending()) {
			return true;
		}
		// 탈퇴한 회원은 lolog-api 데이터가 지워지므로 알릴 것이 없다.
		boolean sent = user.isDeleted() || (user.isSuspended(clock.instant())
				? client.notifySuspended(userId, user.getSuspendedUntil()) : client.notifyUnsuspended(userId));
		if (!sent) {
			log.warn("lolog-api 정지 알림 실패, 다시 부릅니다. userId={}", userId);
			return false;
		}
		tx.executeWithoutResult(status -> users.finishSuspensionNotify(userId, user.getSuspendedAt()));
		return true;
	}

	@Scheduled(fixedDelayString = "${lolog.suspension-notify.retry-delay:PT1M}",
			initialDelayString = "${lolog.suspension-notify.retry-delay:PT1M}")
	public void retryPending() {
		for (User user : users.findBySuspensionNotifyPendingTrue()) {
			tryNotify(user.getId());
		}
	}

}
