package com.lolog.auth.social;

import java.time.Duration;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

// 네이버 액세스 토큰으로 회원 프로필 API(GET /v1/nid/me)를 불러 사용자를 확인한다.
// 네이버는 토큰이 어느 앱(Client ID)의 것인지 알려 주는 API가 없어, 프로필을 받을 수 있으면 맞는 토큰으로 본다.
// 이메일은 사용자가 네이버에 적어 둔 연락처 이메일이라 계정마다 고유하지 않다. 계정은 id로 찾는다.
@Component
public class NaverTokenVerifier {

	// 헤더에 넣을 수 있는 글자만 받는다(줄바꿈 등으로 다른 헤더를 끼워 넣지 못하게).
	private static final Pattern TOKEN = Pattern.compile("[\\x21-\\x7E]+");

	private final RestClient client;

	public NaverTokenVerifier(@Value("${lolog.social.naver.profile-url}") String profileUrl) {
		SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
		requestFactory.setConnectTimeout(Duration.ofSeconds(3));
		requestFactory.setReadTimeout(Duration.ofSeconds(5));
		this.client = RestClient.builder().baseUrl(profileUrl).requestFactory(requestFactory).build();
	}

	// 네이버가 401·403이거나 resultcode가 "00"이 아니면 InvalidProviderTokenException. 네이버 서버 오류·연결 실패는 다른 예외(500)다.
	public SocialProfile verify(String accessToken) {
		if (!TOKEN.matcher(accessToken).matches()) {
			throw new InvalidProviderTokenException("네이버 토큰 모양이 틀렸습니다.");
		}
		NaverProfile body = client.get()
			.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
			.exchange((request, response) -> {
				int status = response.getStatusCode().value();
				if (status == 401 || status == 403) {
					throw new InvalidProviderTokenException("네이버가 토큰을 받지 않았습니다.");
				}
				if (status != 200) {
					throw new IllegalStateException("네이버 프로필 API 응답 " + status);
				}
				return response.bodyTo(NaverProfile.class);
			});
		if (body == null || !"00".equals(body.resultcode()) || body.response() == null || body.response().id() == null
				|| body.response().id().isBlank()) {
			throw new InvalidProviderTokenException("네이버가 사용자를 확인해 주지 않았습니다.");
		}
		return new SocialProfile(body.response().id(), body.response().email());
	}

	// 네이버 프로필 API 응답에서 쓰는 칸만 받는다.
	record NaverProfile(String resultcode, String message, Response response) {

		record Response(String id, String email) {
		}

	}

}
