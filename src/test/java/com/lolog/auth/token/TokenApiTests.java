package com.lolog.auth.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.lolog.auth.MutableClock;
import com.lolog.auth.TestContainers;
import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

// 토큰 갱신·로그아웃(FR-AUTH-03, FR-AUTH-04). Docker가 켜져 있어야 한다.
@SpringBootTest
@AutoConfigureMockMvc
@Import({ TestContainers.class, MutableClock.Config.class })
class TokenApiTests {

	@Autowired
	MockMvc mvc;

	@Autowired
	MutableClock clock;

	@Autowired
	StringRedisTemplate redis;

	@Autowired
	UserRepository users;

	@BeforeEach
	void resetClock() {
		clock.reset();
	}

	@Test
	void 갱신하면_새_토큰_한_벌을_주고_옛_리프레시_토큰은_못_쓴다() throws Exception {
		String refreshToken = signupRefreshToken(newEmail());

		String body = refresh(refreshToken).andExpect(status().isOk())
			.andExpect(jsonPath("$.accessToken").isString())
			.andExpect(jsonPath("$.accessTokenExpiresIn").value(1800))
			.andReturn()
			.getResponse()
			.getContentAsString();
		String newRefreshToken = JsonPath.read(body, "$.refreshToken");
		assertThat(newRefreshToken).isNotEqualTo(refreshToken);

		refresh(refreshToken).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
		refresh(newRefreshToken).andExpect(status().isOk());
	}

	@Test
	void 갱신한_액세스_토큰도_같은_회원이다() throws Exception {
		String signupBody = signup(newEmail());
		String sub = AccessTokens.verify(JsonPath.read(signupBody, "$.accessToken"), AccessTokens.SECRET).getSubject();

		String body = refresh(JsonPath.read(signupBody, "$.refreshToken")).andReturn().getResponse().getContentAsString();

		assertThat(AccessTokens.verify(JsonPath.read(body, "$.accessToken"), AccessTokens.SECRET).getSubject())
			.isEqualTo(sub);
	}

	@Test
	void 없는_리프레시_토큰이면_401_INVALID_TOKEN이다() throws Exception {
		refresh("no-such-token").andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
	}

	@Test
	void 리프레시_토큰은_14일_뒤_만료되고_401_TOKEN_EXPIRED다() throws Exception {
		String almost = signupRefreshToken(newEmail());
		String expired = signupRefreshToken(newEmail());

		clock.advance(Duration.ofDays(14).minusSeconds(1));
		refresh(almost).andExpect(status().isOk());

		clock.advance(Duration.ofSeconds(1));
		refresh(expired).andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("TOKEN_EXPIRED"));
		// 만료된 토큰도 한 번 답하면 지운다.
		refresh(expired).andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
	}

	@Test
	void 탈퇴한_회원의_리프레시_토큰으로는_갱신되지_않는다() throws Exception {
		String email = newEmail();
		String refreshToken = signupRefreshToken(email);
		User user = users.findByEmailAndDeletedAtIsNull(email).orElseThrow();
		user.delete(OffsetDateTime.now());
		users.saveAndFlush(user);

		refresh(refreshToken).andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
	}

	@Test
	void Redis에는_리프레시_토큰_원래_값이_아니라_해시만_둔다() throws Exception {
		String email = newEmail();
		String refreshToken = signupRefreshToken(email);
		long userId = users.findByEmailAndDeletedAtIsNull(email).orElseThrow().getId();

		assertThat(redis.hasKey("lolog:auth:refresh:" + refreshToken)).isFalse();
		assertThat(redis.hasKey("lolog:auth:refresh:" + RefreshTokenStore.hash(refreshToken))).isTrue();
		Set<String> userTokens = redis.opsForSet().members("lolog:auth:user-refresh:" + userId);
		assertThat(userTokens).containsExactly(RefreshTokenStore.hash(refreshToken));
		// 키는 만료 뒤 하루 더 남긴다(TOKEN_EXPIRED로 답하려고).
		assertThat(redis.getExpire("lolog:auth:refresh:" + RefreshTokenStore.hash(refreshToken)))
			.isBetween(Duration.ofDays(15).minusMinutes(1).toSeconds(), Duration.ofDays(15).toSeconds());
	}

	@Test
	void 로그아웃하면_204이고_그_리프레시_토큰은_못_쓴다() throws Exception {
		String refreshToken = signupRefreshToken(newEmail());

		logout(refreshToken).andExpect(status().isNoContent());

		refresh(refreshToken).andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
	}

	@Test
	void 없거나_이미_로그아웃한_토큰으로_로그아웃해도_204다() throws Exception {
		logout("no-such-token").andExpect(status().isNoContent());
		String refreshToken = signupRefreshToken(newEmail());
		logout(refreshToken).andExpect(status().isNoContent());
		logout(refreshToken).andExpect(status().isNoContent());
	}

	@Test
	void 리프레시_토큰이_빠지면_400_INVALID_REQUEST다() throws Exception {
		mvc.perform(post("/auth/refresh").contentType(MediaType.APPLICATION_JSON).content("{}"))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.field").value("refreshToken"));
		mvc.perform(post("/auth/logout").contentType(MediaType.APPLICATION_JSON).content("{}"))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.field").value("refreshToken"));
	}

	private String signup(String email) throws Exception {
		return mvc
			.perform(post("/auth/signup").contentType(MediaType.APPLICATION_JSON)
				.content("{\"email\":\"" + email + "\",\"password\":\"password1\"}"))
			.andExpect(status().isCreated())
			.andReturn()
			.getResponse()
			.getContentAsString();
	}

	private String signupRefreshToken(String email) throws Exception {
		return JsonPath.read(signup(email), "$.refreshToken");
	}

	private ResultActions refresh(String refreshToken) throws Exception {
		return mvc.perform(post("/auth/refresh").contentType(MediaType.APPLICATION_JSON)
			.content("{\"refreshToken\":\"" + refreshToken + "\"}"));
	}

	private ResultActions logout(String refreshToken) throws Exception {
		return mvc.perform(post("/auth/logout").contentType(MediaType.APPLICATION_JSON)
			.content("{\"refreshToken\":\"" + refreshToken + "\"}"));
	}

	private static String newEmail() {
		return "u" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
	}

}
