package com.lolog.auth.user;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

	// 살아 있는 회원만 찾는다. 이메일은 User.normalizeEmail로 바꾼 값을 넘긴다.
	Optional<User> findByEmailAndDeletedAtIsNull(String email);

	boolean existsByEmailAndDeletedAtIsNull(String email);

	Optional<User> findByIdAndDeletedAtIsNull(Long id);

	// 탈퇴했지만 lolog-api 데이터 삭제가 아직 끝나지 않은 회원
	List<User> findByDeletedAtIsNotNullAndDataDeletedAtIsNull();

}
