package com.lolog.auth.me;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.lolog.auth.TestContainers;
import com.lolog.auth.token.WithdrawnUsers;
import com.lolog.auth.user.SocialAccount;
import com.lolog.auth.user.SocialAccountRepository;
import com.lolog.auth.user.SocialProvider;
import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import java.io.IOException;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

// 회원 탈퇴(FR-AUTH-05). lolog-api는 가짜 서버로 대신한다. Docker가 켜져 있어야 한다.
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestContainers.class)
class WithdrawApiTests {

	static final FakeLologApi api;

	static {
		try {
			api = new FakeLologApi();
		}
		catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	@DynamicPropertySource
	static void apiUrl(DynamicPropertyRegistry registry) {
		registry.add("lolog.api.internal-url", api::url);
	}

	@Autowired
	MockMvc mvc;

	@Autowired
	UserRepository users;

	@Autowired
	SocialAccountRepository socialAccounts;

	@Autowired
	UserDataDeleter deleter;

	@Autowired
	StringRedisTemplate redis;

	@BeforeEach
	void resetApi() {
		api.reset();
		// 다른 테스트가 남긴 "다시 부를 회원"을 정리해, 요청 기록에 섞이지 않게 한다.
		deleter.retryPending();
		api.reset();
	}

	@Test
	void 탈퇴하면_204이고_회원과_소셜_연결을_소프트_삭제한다() throws Exception {
		String email = newEmail();
		String token = accessToken(signup(email));
		long userId = users.findByEmailAndDeletedAtIsNull(email).orElseThrow().getId();
		socialAccounts.saveAndFlush(new SocialAccount(userId, SocialProvider.KAKAO, "k-" + userId, OffsetDateTime.now()));

		withdraw(token).andExpect(status().isNoContent());

		User user = users.findById(userId).orElseThrow();
		assertThat(user.getDeletedAt()).isNotNull();
		assertThat(socialAccounts.findByUserIdAndDeletedAtIsNull(userId)).isEmpty();
		assertThat(socialAccounts.findAll()).filteredOn(a -> a.getUserId() == userId)
			.allSatisfy(a -> assertThat(a.getDeletedAt()).isNotNull());
	}

	@Test
	void 탈퇴하면_lolog_api에_내부_토큰을_붙여_데이터_삭제를_부른다() throws Exception {
		String email = newEmail();
		String token = accessToken(signup(email));
		long userId = users.findByEmailAndDeletedAtIsNull(email).orElseThrow().getId();

		withdraw(token).andExpect(status().isNoContent());

		assertThat(api.requests).containsExactly("DELETE /internal/users/" + userId + " internal-test-token");
		assertThat(users.findById(userId).orElseThrow().getDataDeletedAt()).isNotNull();
	}

	@Test
	void 탈퇴하면_그_회원의_리프레시_토큰을_모두_못_쓴다() throws Exception {
		String email = newEmail();
		String first = signup(email);
		String second = login(email);

		withdraw(accessToken(first)).andExpect(status().isNoContent());

		refresh(JsonPath.read(first, "$.refreshToken")).andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
		refresh(JsonPath.read(second, "$.refreshToken")).andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
	}

	@Test
	void 탈퇴하면_lolog_api가_남은_액세스_토큰을_막도록_Redis에_31분_동안_남긴다() throws Exception {
		String email = newEmail();
		String token = accessToken(signup(email));
		long userId = users.findByEmailAndDeletedAtIsNull(email).orElseThrow().getId();
		assertThat(redis.hasKey("lolog:auth:withdrawn:" + userId)).isFalse();

		withdraw(token).andExpect(status().isNoContent());

		String key = "lolog:auth:withdrawn:" + userId;
		assertThat(redis.opsForValue().get(key)).matches("\\d+");
		// 키 이름과 31분은 lolog-api와 같이 쓰는 약속이라 값으로 적어 둔다.
		assertThat(WithdrawnUsers.TTL).isEqualTo(Duration.ofMinutes(31));
		assertThat(Duration.ofSeconds(redis.getExpire(key))).isBetween(Duration.ofMinutes(31).minusSeconds(5),
				Duration.ofMinutes(31));
	}

	@Test
	void 탈퇴한_뒤에는_로그인되지_않고_같은_이메일로_다시_가입할_수_있다() throws Exception {
		String email = newEmail();
		withdraw(accessToken(signup(email))).andExpect(status().isNoContent());

		mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(json(email)))
			.andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
		mvc.perform(post("/auth/signup").contentType(MediaType.APPLICATION_JSON).content(json(email)))
			.andExpect(status().isCreated());
	}

	@Test
	void 같은_토큰으로_다시_탈퇴하면_401_INVALID_TOKEN이다() throws Exception {
		String token = accessToken(signup(newEmail()));
		withdraw(token).andExpect(status().isNoContent());

		withdraw(token).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
	}

	@Test
	void 토큰이_없으면_401_INVALID_TOKEN이고_아무것도_지우지_않는다() throws Exception {
		mvc.perform(delete("/auth/me")).andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
		assertThat(api.requests).isEmpty();
	}

	@Test
	void lolog_api가_실패해도_204이고_204가_올_때까지_다시_부른다() throws Exception {
		String email = newEmail();
		String token = accessToken(signup(email));
		long userId = users.findByEmailAndDeletedAtIsNull(email).orElseThrow().getId();
		api.status.set(500);

		withdraw(token).andExpect(status().isNoContent());
		assertThat(users.findById(userId).orElseThrow().getDataDeletedAt()).isNull();

		deleter.retryPending();
		assertThat(users.findById(userId).orElseThrow().getDataDeletedAt()).isNull();

		api.status.set(204);
		deleter.retryPending();
		assertThat(users.findById(userId).orElseThrow().getDataDeletedAt()).isNotNull();
		assertThat(api.requests).hasSize(3).allMatch(r -> r.equals("DELETE /internal/users/" + userId + " internal-test-token"));

		// 끝난 회원은 다시 부르지 않는다.
		deleter.retryPending();
		assertThat(api.requests).hasSize(3);
	}

	private ResultActions withdraw(String accessToken) throws Exception {
		return mvc.perform(delete("/auth/me").header("Authorization", "Bearer " + accessToken));
	}

	private ResultActions refresh(String refreshToken) throws Exception {
		return mvc.perform(post("/auth/refresh").contentType(MediaType.APPLICATION_JSON)
			.content("{\"refreshToken\":\"" + refreshToken + "\"}"));
	}

	private String signup(String email) throws Exception {
		return mvc.perform(post("/auth/signup").contentType(MediaType.APPLICATION_JSON).content(json(email)))
			.andExpect(status().isCreated())
			.andReturn()
			.getResponse()
			.getContentAsString();
	}

	private String login(String email) throws Exception {
		return mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(json(email)))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString();
	}

	private static String accessToken(String tokenResponse) {
		return JsonPath.read(tokenResponse, "$.accessToken");
	}

	private static String json(String email) {
		return "{\"email\":\"" + email + "\",\"password\":\"password1\"}";
	}

	private static String newEmail() {
		return "u" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
	}

}
