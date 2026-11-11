package com.lolog.auth.admin;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

// 관리자 테스트용 가짜 lolog-api. 받은 요청을 "메서드 경로 내부토큰 본문" 모양으로 남기고, 정해 둔 상태 코드로 답한다.
final class FakeSuspensionApi {

	private final HttpServer server;

	final AtomicInteger status = new AtomicInteger(204);

	final List<String> requests = new CopyOnWriteArrayList<>();

	FakeSuspensionApi() throws IOException {
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/", exchange -> {
			String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
			requests.add((exchange.getRequestMethod() + " " + exchange.getRequestURI().getPath() + " "
					+ exchange.getRequestHeaders().getFirst("X-Internal-Token") + " " + body).strip());
			exchange.sendResponseHeaders(status.get(), -1);
			exchange.close();
		});
		server.start();
	}

	String url() {
		return "http://127.0.0.1:" + server.getAddress().getPort();
	}

	void reset() {
		status.set(204);
		requests.clear();
	}

	// 그 회원에 대한 요청만
	List<String> requestsFor(long userId) {
		return requests.stream().filter(r -> r.contains("/internal/users/" + userId + "/")).toList();
	}

}
