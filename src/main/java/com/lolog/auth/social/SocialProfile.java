package com.lolog.auth.social;

// 소셜 회사가 확인해 준 사용자. providerUserId는 그 회사 안에서 바뀌지 않는 ID이고, 계정은 이 값으로 찾는다.
// email은 회사가 주지 않았거나(동의 안 함) 인증되지 않은 이메일이면 null이다.
public record SocialProfile(String providerUserId, String email) {
}
