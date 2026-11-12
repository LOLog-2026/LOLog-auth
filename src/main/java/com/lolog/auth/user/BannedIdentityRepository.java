package com.lolog.auth.user;

import org.springframework.data.jpa.repository.JpaRepository;

public interface BannedIdentityRepository extends JpaRepository<BannedIdentity, Long> {

	boolean existsByKindAndValue(BannedIdentity.Kind kind, String value);

	// 이메일은 User.normalizeEmail로 바꾼 값을 넘긴다.
	default boolean isEmailBanned(String email) {
		return existsByKindAndValue(BannedIdentity.Kind.EMAIL, email);
	}

	default boolean isSocialBanned(SocialProvider provider, String providerUserId) {
		return existsByKindAndValue(BannedIdentity.Kind.of(provider), providerUserId);
	}

}
