package com.lolog.auth.social;

// 소셜 회사가 providerToken을 확인해 주지 않았다(틀림, 만료, 다른 앱의 토큰 등). 회사 서버가 아파서 확인을 못 한 경우는 이 예외가 아니다.
public class InvalidProviderTokenException extends RuntimeException {

	public InvalidProviderTokenException(String message) {
		super(message);
	}

}
