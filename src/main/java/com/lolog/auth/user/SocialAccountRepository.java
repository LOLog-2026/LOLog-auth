package com.lolog.auth.user;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SocialAccountRepository extends JpaRepository<SocialAccount, Long> {

	Optional<SocialAccount> findByProviderAndProviderUserIdAndDeletedAtIsNull(SocialProvider provider,
			String providerUserId);

	List<SocialAccount> findByUserIdAndDeletedAtIsNull(Long userId);

}
