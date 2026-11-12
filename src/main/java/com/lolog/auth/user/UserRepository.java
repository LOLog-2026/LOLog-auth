package com.lolog.auth.user;

import jakarta.persistence.LockModeType;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<User, Long> {

	// 살아 있는 회원만 찾는다. 이메일은 User.normalizeEmail로 바꾼 값을 넘긴다.
	Optional<User> findByEmailAndDeletedAtIsNull(String email);

	boolean existsByEmailAndDeletedAtIsNull(String email);

	Optional<User> findByIdAndDeletedAtIsNull(Long id);

	// 살아 있는 회원을 찾으며 그 행을 잠근다. 연동 해제가 동시에 와서 로그인 수단이 다 없어지지 않게 한다.
	@Lock(LockModeType.PESSIMISTIC_WRITE)
	@Query("select u from User u where u.id = :id and u.deletedAt is null")
	Optional<User> lockActive(@Param("id") Long id);

	// 탈퇴했지만 lolog-api 데이터 삭제가 아직 끝나지 않은 회원
	List<User> findByDeletedAtIsNotNullAndDataDeletedAtIsNull();

	// 정지·해제를 lolog-api에 아직 알리지 못한 회원(#22)
	List<User> findBySuspensionNotifyPendingTrue();

	// 알린 정지 상태가 지금도 그대로일 때만 알림 대기를 끝낸다. 알리는 동안 관리자가 다시 정지·해제했으면
	// suspended_at이 달라져 그대로 남고, 다음 주기에 새 상태를 다시 알린다.
	@Modifying
	@Query(value = "UPDATE users SET suspension_notify_pending = FALSE WHERE id = :id AND suspension_notify_pending "
			+ "AND suspended_at IS NOT DISTINCT FROM CAST(:suspendedAt AS TIMESTAMPTZ)", nativeQuery = true)
	int finishSuspensionNotify(@Param("id") long id, @Param("suspendedAt") OffsetDateTime suspendedAt);

}
