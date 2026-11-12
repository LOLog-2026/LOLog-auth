package com.lolog.auth.token;

import com.lolog.auth.common.ApiException;
import java.util.List;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

// @CurrentUser Long userId 인자를 채운다. 로그인이 필요한 주소만 이 인자를 받으므로 나머지 주소는 토큰을 보지 않는다.
// 정지된 회원이 정지 전에 받은 토큰은 401 INVALID_TOKEN이다(spec/admin.md 2장). 탈퇴한 회원의 토큰도 같다.
// 탈퇴 키를 여기서도 봐서, 요청 값 검사(400)보다 토큰 확인(401)이 먼저 일어난다(api-spec.md). 각 서비스의 DB 확인은 그대로 둔다.
@Configuration(proxyBeanMethods = false)
public class CurrentUserResolver implements HandlerMethodArgumentResolver, WebMvcConfigurer {

	private final AccessTokenVerifier verifier;

	private final SuspendedUsers suspendedUsers;

	private final WithdrawnUsers withdrawnUsers;

	public CurrentUserResolver(AccessTokenVerifier verifier, SuspendedUsers suspendedUsers,
			WithdrawnUsers withdrawnUsers) {
		this.verifier = verifier;
		this.suspendedUsers = suspendedUsers;
		this.withdrawnUsers = withdrawnUsers;
	}

	@Override
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
		resolvers.add(this);
	}

	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		return parameter.hasParameterAnnotation(CurrentUser.class) && parameter.getParameterType() == Long.class;
	}

	@Override
	public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
			NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
		long userId = verifier.verify(webRequest.getHeader(HttpHeaders.AUTHORIZATION));
		if (suspendedUsers.contains(userId)) {
			throw new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_TOKEN", "정지된 회원의 토큰입니다.");
		}
		if (withdrawnUsers.contains(userId)) {
			throw new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_TOKEN", "탈퇴한 회원의 토큰입니다.");
		}
		return userId;
	}

}
