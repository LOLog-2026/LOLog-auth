package com.lolog.auth.token;

import java.util.List;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

// @CurrentUser Long userId 인자를 채운다. 로그인이 필요한 주소만 이 인자를 받으므로 나머지 주소는 토큰을 보지 않는다.
@Configuration(proxyBeanMethods = false)
public class CurrentUserResolver implements HandlerMethodArgumentResolver, WebMvcConfigurer {

	private final AccessTokenVerifier verifier;

	public CurrentUserResolver(AccessTokenVerifier verifier) {
		this.verifier = verifier;
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
		return verifier.verify(webRequest.getHeader(HttpHeaders.AUTHORIZATION));
	}

}
