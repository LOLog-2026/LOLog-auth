package com.lolog.auth.user;

import java.util.Locale;
import java.util.Optional;

// 소셜 로그인 회사. 주소에서는 소문자(kakao), 응답의 linkedProviders에서는 대문자(KAKAO)다(api-spec.md).
public enum SocialProvider {

	KAKAO, GOOGLE, NAVER;

	// 주소의 {provider}를 바꾼다. 소문자만 받는다.
	public static Optional<SocialProvider> fromPath(String value) {
		for (SocialProvider provider : values()) {
			if (provider.name().toLowerCase(Locale.ROOT).equals(value)) {
				return Optional.of(provider);
			}
		}
		return Optional.empty();
	}

}
