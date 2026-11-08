package com.lolog.auth.me;

import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

// lolog-api에 탈퇴한 회원의 데이터를 지워 달라고 한다: DELETE /internal/users/{id} (api-dto.md).
// 같은 요청을 여러 번 불러도 되고, 지울 게 없어도 204다. 이미지를 못 지우면 500이 오므로 204가 올 때까지 다시 부른다.
@Component
public class UserDataClient {

	private final RestClient client;

	public UserDataClient(@Value("${lolog.api.internal-url}") String baseUrl,
			@Value("${lolog.internal.token}") String internalToken) {
		// 이미지를 여러 장 지우면 오래 걸릴 수 있어 읽기는 넉넉히 기다린다.
		SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
		requestFactory.setConnectTimeout(Duration.ofSeconds(2));
		requestFactory.setReadTimeout(Duration.ofSeconds(30));
		this.client = RestClient.builder()
			.baseUrl(baseUrl)
			.requestFactory(requestFactory)
			.defaultHeader("X-Internal-Token", internalToken)
			.build();
	}

	// 204면 true. 다른 응답이나 연결 실패는 false(다시 부를 대상)다.
	public boolean deleteUserData(long userId) {
		try {
			return client.delete()
				.uri("/internal/users/{id}", userId)
				.exchange((request, response) -> response.getStatusCode().value() == 204);
		}
		catch (RestClientException e) {
			return false;
		}
	}

}
