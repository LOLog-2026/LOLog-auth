package com.lolog.auth.me;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

// 탈퇴 테스트용 가짜 lolog-api. DELETE /internal/users/{id}를 받아 기록하고, 정해 둔 상태 코드로 답한다.
final class FakeLologApi {

	private final HttpServer server;

	final AtomicInteger status = new AtomicInteger(204);

	final List<String> requests = new CopyOnWriteArrayList<>();

	FakeLologApi() throws IOException {
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/", exchange -> {
			// "메서드 경로 내부토큰" 모양으로 남긴다.
			requests.add(exchange.getRequestMethod() + " " + exchange.getRequestURI().getPath() + " "
					+ exchange.getRequestHeaders().getFirst("X-Internal-Token"));
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

}
