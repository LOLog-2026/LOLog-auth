package com.lolog.auth.user;

import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
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

}
