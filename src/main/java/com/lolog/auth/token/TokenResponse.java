package com.lolog.auth.token;

// 가입 201, 로그인·갱신 200의 본문(api-dto.md TokenResponse). accessTokenExpiresIn은 액세스 토큰 남은 시간(초)이다.
public record TokenResponse(String accessToken, String refreshToken, int accessTokenExpiresIn) {

}
