package com.lolog.auth;

import com.lolog.auth.email.EmailCodeStore;
import com.lolog.auth.user.User;

// 가입 인증이 주제가 아닌 테스트에서 가입할 때 쓴다. 메일 없이 그 이메일에 인증번호를 바로 둔다.
public final class SignupCodes {

	public static final String CODE = "123456";

	private SignupCodes() {
	}

	// 가입 본문 JSON. 부르기 전에 그 이메일에 CODE를 둔다.
	public static String signupJson(EmailCodeStore codes, String email, String password) {
		codes.save(User.normalizeEmail(email), CODE);
		return "{\"email\":\"" + email + "\",\"password\":\"" + password + "\",\"code\":\"" + CODE + "\"}";
	}

}
