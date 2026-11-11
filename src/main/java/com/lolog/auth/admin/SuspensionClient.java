package com.lolog.auth.admin;

import java.time.Duration;
import java.time.OffsetDateTime;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

// lolog-api에 정지·해제를 알린다(LOLog-docs PR #59 spec/admin.md 7장 /internal, 초안).
// PUT /internal/users/{id}/suspension { suspendedUntil } (영구면 null), DELETE /internal/users/{id}/suspension.
// 방 멤버 목록의 "정지된 계정" 표시에 쓰인다. 같은 요청을 여러 번 불러도 되는 주소라 204가 올 때까지 다시 부른다.
@Component
public class SuspensionClient {

	private final RestClient client;

	public SuspensionClient(@Value("${lolog.api.internal-url}") String baseUrl,
			@Value("${lolog.internal.token}") String internalToken) {
		SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
		requestFactory.setConnectTimeout(Duration.ofSeconds(2));
		requestFactory.setReadTimeout(Duration.ofSeconds(5));
		this.client = RestClient.builder()
			.baseUrl(baseUrl)
			.requestFactory(requestFactory)
			.defaultHeader("X-Internal-Token", internalToken)
			.build();
	}

	// 204면 true. 다른 응답이나 연결 실패는 false(다시 부를 대상)다.
	public boolean notifySuspended(long userId, OffsetDateTime suspendedUntil) {
		try {
			return client.put()
				.uri("/internal/users/{id}/suspension", userId)
				.contentType(MediaType.APPLICATION_JSON)
				.body(new SuspensionBody(suspendedUntil))
				.exchange((request, response) -> response.getStatusCode().value() == 204);
		}
		catch (RestClientException e) {
			return false;
		}
	}

	public boolean notifyUnsuspended(long userId) {
		try {
			return client.delete()
				.uri("/internal/users/{id}/suspension", userId)
				.exchange((request, response) -> response.getStatusCode().value() == 204);
		}
		catch (RestClientException e) {
			return false;
		}
	}

	record SuspensionBody(OffsetDateTime suspendedUntil) {
	}

}
