package com.lolog.auth.social;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

// 소셜 로그인 테스트용 가짜 구글·네이버.
// 구글: /google/certs에 공개 키(JWKS)를 두고, idToken()으로 그 키로 서명한 ID 토큰을 만든다.
// 네이버: /naver/me가 토큰마다 정해 둔 프로필을 돌려주고, 모르는 토큰이면 401이다.
final class FakeSocialProviders {

	static final String WEB_CLIENT_ID = "test-web-client.apps.googleusercontent.com";

	private final HttpServer server;

	private final RSAKey key;

	// 서명 키는 맞지만 JWKS에 없는 키(가짜 서명 시험용)
	private final RSAKey otherKey;

	final Map<String, String> naverProfiles = new ConcurrentHashMap<>();

	final AtomicInteger naverStatus = new AtomicInteger(0);

	final List<String> naverAuthHeaders = new CopyOnWriteArrayList<>();

	FakeSocialProviders() throws IOException, JOSEException {
		key = new RSAKeyGenerator(2048).keyID("test-key").generate();
		otherKey = new RSAKeyGenerator(2048).keyID("test-key").generate();
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/google/certs", exchange -> {
			byte[] body = new JWKSet(key.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);
			exchange.getResponseHeaders().add("Content-Type", "application/json");
			exchange.sendResponseHeaders(200, body.length);
			exchange.getResponseBody().write(body);
			exchange.close();
		});
		server.createContext("/naver/me", exchange -> {
			String auth = exchange.getRequestHeaders().getFirst("Authorization");
			naverAuthHeaders.add(auth);
			String token = auth != null && auth.startsWith("Bearer ") ? auth.substring(7) : "";
			String profile = naverProfiles.get(token);
			int status = naverStatus.get() != 0 ? naverStatus.get() : (profile != null ? 200 : 401);
			byte[] body = (status == 200 ? profile
					: "{\"resultcode\":\"024\",\"message\":\"Authentication failed\"}")
				.getBytes(StandardCharsets.UTF_8);
			exchange.getResponseHeaders().add("Content-Type", "application/json");
			exchange.sendResponseHeaders(status, body.length);
			exchange.getResponseBody().write(body);
			exchange.close();
		});
		server.start();
	}

	String url() {
		return "http://127.0.0.1:" + server.getAddress().getPort();
	}

	void reset() {
		naverProfiles.clear();
		naverStatus.set(0);
		naverAuthHeaders.clear();
	}

	// 구글이 주는 모양의 ID 토큰. 바꾸고 싶은 클레임만 claims로 덮어쓴다(값이 null이면 뺀다).
	String idToken(String sub, String email, Map<String, Object> claims) throws JOSEException {
		return sign(key, sub, email, claims);
	}

	String idTokenSignedByOtherKey(String sub, String email) throws JOSEException {
		return sign(otherKey, sub, email, Map.of());
	}

	private static String sign(RSAKey signingKey, String sub, String email, Map<String, Object> overrides)
			throws JOSEException {
		Instant now = Instant.now();
		Map<String, Object> claims = new java.util.HashMap<>();
		claims.put("iss", "https://accounts.google.com");
		claims.put("aud", WEB_CLIENT_ID);
		claims.put("azp", "android-client.apps.googleusercontent.com");
		claims.put("sub", sub);
		claims.put("email", email);
		claims.put("email_verified", true);
		claims.put("iat", Date.from(now));
		claims.put("exp", Date.from(now.plusSeconds(3600)));
		claims.putAll(overrides);
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
		claims.forEach((name, value) -> {
			if (value != null) {
				builder.claim(name, value);
			}
		});
		SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(),
				builder.build());
		jwt.sign(new RSASSASigner(signingKey));
		return jwt.serialize();
	}

	static String naverProfile(String id, String email) {
		String emailField = email == null ? "" : ",\"email\":\"" + email + "\"";
		return "{\"resultcode\":\"00\",\"message\":\"success\",\"response\":{\"id\":\"" + id + "\"" + emailField
				+ ",\"nickname\":\"테스트\"}}";
	}

}
