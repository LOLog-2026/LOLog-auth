package com.lolog.auth.token;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

// 컨트롤러 인자에 붙이면 Authorization: Bearer <액세스 토큰>을 검사해 회원 ID(Long)를 넣는다.
// 토큰이 없거나 틀리면 401 INVALID_TOKEN, 만료면 401 TOKEN_EXPIRED(LOLog-docs PR #29).
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
public @interface CurrentUser {

}
