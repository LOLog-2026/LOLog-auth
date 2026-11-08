package com.lolog.auth.common;

// 모든 4xx·5xx 응답의 본문(api-dto.md ErrorResponse). field는 400 INVALID_REQUEST일 때만 채우고, 다른 오류는 null이다.
public record ErrorResponse(String code, String message, String field) {

	public ErrorResponse(String code, String message) {
		this(code, message, null);
	}

}
