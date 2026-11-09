package com.lolog.auth.me;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.lolog.auth.MutableClock;
import com.lolog.auth.SignupCodes;
import com.lolog.auth.email.EmailCodeStore;
import com.lolog.auth.TestContainers;
import com.lolog.auth.token.AccessTokens;
import com.lolog.auth.user.SocialAccount;
import com.lolog.auth.user.SocialAccountRepository;
import com.lolog.auth.user.SocialProvider;
import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

// 내 정보 보기와 로그인이 필요한 /auth 주소의 액세스 토큰 검사. Docker가 켜져 있어야 한다.
@SpringBootTest
@AutoConfigureMockMvc
@Import({ TestContainers.class, MutableClock.Config.class })
class MeApiTests {

	@Autowired
	EmailCodeStore codes;

	@Autowired
	MockMvc mvc;

	@Autowired
	UserRepository users;

	@Autowired
	SocialAccountRepository socialAccounts;

	@Autowired
	MutableClock clock;

	@BeforeEach
	void resetClock() {
		clock.reset();
	}

	@Test
	void 내_이메일과_빈_연결_목록을_준다() throws Exception {
		String email = newEmail();
		String token = signupAccessToken(email);

		me("Bearer " + token).andExpect(status().isOk())
			.andExpect(jsonPath("$.email").value(email))
			.andExpect(jsonPath("$.linkedProviders").isArray())
			.andExpect(jsonPath("$.linkedProviders.length()").value(0));
	}

	@Test
	void 연결된_소셜_계정은_대문자로_KAKAO_GOOGLE_NAVER_순서다() throws Exception {
		String email = newEmail();
		String token = signupAccessToken(email);
		long userId = users.findByEmailAndDeletedAtIsNull(email).orElseThrow().getId();
		OffsetDateTime now = OffsetDateTime.now();
		socialAccounts.save(new SocialAccount(userId, SocialProvider.NAVER, "n-" + userId, now));
		socialAccounts.save(new SocialAccount(userId, SocialProvider.KAKAO, "k-" + userId, now));
		SocialAccount google = socialAccounts.save(new SocialAccount(userId, SocialProvider.GOOGLE, "g-" + userId, now));
		google.delete(now);
		socialAccounts.saveAndFlush(google);

		me("Bearer " + token).andExpect(jsonPath("$.linkedProviders[0]").value("KAKAO"))
			.andExpect(jsonPath("$.linkedProviders[1]").value("NAVER"))
			.andExpect(jsonPath("$.linkedProviders.length()").value(2));
	}

	// iat가 빠진 토큰은 여기 넣지 않았다. Spring의 JWT 변환기가 iat를 exp - 1초로 채워 넣어 통과시킨다.
	// lolog-api도 같은 라이브러리라 똑같이 동작하고, 우리 서버는 늘 iat를 넣어 발급한다.
	@Test
	void 토큰이_없거나_틀리면_401_INVALID_TOKEN이다() throws Exception {
		Instant now = Instant.now();
		String other = "another-secret-at-least-32-bytes-long!!";
		for (String header : new String[] { null, "", "Bearer", "Bearer not-a-jwt", "Basic abc",
				"Bearer " + AccessTokens.token("1", "access", now, now.plusSeconds(1800), other),
				"Bearer " + AccessTokens.token("1", "refresh", now, now.plusSeconds(1800), AccessTokens.SECRET),
				"Bearer " + AccessTokens.token("1", null, now, now.plusSeconds(1800), AccessTokens.SECRET),
				"Bearer " + AccessTokens.token("abc", "access", now, now.plusSeconds(1800), AccessTokens.SECRET),
				"Bearer " + AccessTokens.token("1", "access", now, null, AccessTokens.SECRET) }) {
			me(header).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
		}
	}

	@Test
	void 만료된_토큰은_401_TOKEN_EXPIRED이고_30초까지는_봐준다() throws Exception {
		String token = signupAccessToken(newEmail());

		clock.advance(Duration.ofMinutes(30).plusSeconds(30));
		me("Bearer " + token).andExpect(status().isOk());

		clock.advance(Duration.ofSeconds(1));
		me("Bearer " + token).andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("TOKEN_EXPIRED"));
	}

	@Test
	void 탈퇴한_회원의_토큰이면_401_INVALID_TOKEN이다() throws Exception {
		String email = newEmail();
		String token = signupAccessToken(email);
		User user = users.findByEmailAndDeletedAtIsNull(email).orElseThrow();
		user.delete(OffsetDateTime.now());
		users.saveAndFlush(user);

		me("Bearer " + token).andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
	}

	@Test
	void 로그인이_필요_없는_주소는_토큰을_보지_않는다() throws Exception {
		mvc.perform(post("/auth/login").header("Authorization", "Bearer broken")
			.contentType(MediaType.APPLICATION_JSON)
			.content("{\"email\":\"" + newEmail() + "\",\"password\":\"password1\"}"))
			.andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
	}

	private ResultActions me(String authorization) throws Exception {
		var request = get("/auth/me");
		if (authorization != null) {
			request.header("Authorization", authorization);
		}
		return mvc.perform(request);
	}

	private String signupAccessToken(String email) throws Exception {
		String body = mvc
			.perform(post("/auth/signup").contentType(MediaType.APPLICATION_JSON)
				.content(SignupCodes.signupJson(codes, email, "password1")))
			.andExpect(status().isCreated())
			.andReturn()
			.getResponse()
			.getContentAsString();
		return JsonPath.read(body, "$.accessToken");
	}

	private static String newEmail() {
		return "u" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
	}

}
