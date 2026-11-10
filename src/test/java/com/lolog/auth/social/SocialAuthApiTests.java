package com.lolog.auth.social;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.lolog.auth.TestContainers;
import com.lolog.auth.me.MeService;
import com.lolog.auth.token.TokenService;
import com.lolog.auth.user.SocialAccount;
import com.lolog.auth.user.SocialAccountRepository;
import com.lolog.auth.user.SocialProvider;
import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

// 소셜 로그인(FR-AUTH-02)과 계정 연결·해제(FR-AUTH-06). 구글·네이버는 가짜 서버로 대신한다. Docker가 켜져 있어야 한다.
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestContainers.class)
class SocialAuthApiTests {

	static final FakeSocialProviders fake;

	static {
		try {
			fake = new FakeSocialProviders();
		}
		catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	@DynamicPropertySource
	static void providers(DynamicPropertyRegistry registry) {
		registry.add("lolog.social.google.client-id", () -> FakeSocialProviders.WEB_CLIENT_ID);
		registry.add("lolog.social.google.jwk-set-uri", () -> fake.url() + "/google/certs");
		registry.add("lolog.social.naver.profile-url", () -> fake.url() + "/naver/me");
	}

	@Autowired
	MockMvc mvc;

	@Autowired
	UserRepository users;

	@Autowired
	SocialAccountRepository socialAccounts;

	@Autowired
	TokenService tokens;

	@Autowired
	MeService me;

	@BeforeEach
	void reset() {
		fake.reset();
	}

	// ── 구글 로그인 ──

	@Test
	void 구글로_처음_로그인하면_200_isNewUser_true이고_소문자_이메일로_가입된다() throws Exception {
		String sub = newId();
		String email = "G" + sub + "@Gmail.com";

		String body = social("google", fake.idToken(sub, email, Map.of())).andExpect(status().isOk())
			.andExpect(jsonPath("$.accessToken").isString())
			.andExpect(jsonPath("$.refreshToken").isString())
			.andExpect(jsonPath("$.accessTokenExpiresIn").value(1800))
			.andExpect(jsonPath("$.isNewUser").value(true))
			.andReturn()
			.getResponse()
			.getContentAsString();

		User user = users.findByEmailAndDeletedAtIsNull(email.toLowerCase()).orElseThrow();
		assertThat(user.getPasswordHash()).isNull();
		assertThat(socialAccounts.findByProviderAndProviderUserIdAndDeletedAtIsNull(SocialProvider.GOOGLE, sub))
			.get()
			.extracting(SocialAccount::getUserId)
			.isEqualTo(user.getId());
		// 받은 토큰으로 내 정보를 볼 수 있다.
		mvc.perform(get("/auth/me").header("Authorization", "Bearer " + JsonPath.read(body, "$.accessToken")))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.email").value(email.toLowerCase()))
			.andExpect(jsonPath("$.linkedProviders[0]").value("GOOGLE"));
	}

	@Test
	void 같은_구글_계정으로_다시_로그인하면_isNewUser_false이고_같은_회원이다() throws Exception {
		String sub = newId();
		social("google", fake.idToken(sub, sub + "@gmail.com", Map.of())).andExpect(status().isOk());
		long count = users.count();

		// 구글에서 이메일을 바꿨어도 sub로 찾는다.
		social("google", fake.idToken(sub, "changed-" + sub + "@gmail.com", Map.of())).andExpect(status().isOk())
			.andExpect(jsonPath("$.isNewUser").value(false));
		assertThat(users.count()).isEqualTo(count);
	}

	@Test
	void 구글_토큰의_aud가_웹_클라이언트_ID가_아니면_401_INVALID_TOKEN이다() throws Exception {
		social("google", fake.idToken(newId(), newId() + "@gmail.com", Map.of("aud", "other-app")))
			.andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
	}

	@Test
	void 구글_토큰의_발급자가_구글이_아니면_401이다() throws Exception {
		social("google", fake.idToken(newId(), newId() + "@gmail.com", Map.of("iss", "https://evil.example.com")))
			.andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
	}

	@Test
	void 만료된_구글_토큰은_401이다() throws Exception {
		Instant past = Instant.now().minusSeconds(7200);
		social("google",
				fake.idToken(newId(), newId() + "@gmail.com",
						Map.of("iat", Date.from(past), "exp", Date.from(past.plusSeconds(3600)))))
			.andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
	}

	@Test
	void 구글_공개_키로_서명하지_않은_토큰과_JWT가_아닌_값은_401이다() throws Exception {
		social("google", fake.idTokenSignedByOtherKey(newId(), newId() + "@gmail.com"))
			.andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
		social("google", "not-a-jwt").andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
	}

	@Test
	void 구글이_인증하지_않은_이메일이거나_이메일이_없으면_401이고_가입되지_않는다() throws Exception {
		String sub = newId();
		Map<String, Object> unverified = new HashMap<>();
		unverified.put("email_verified", false);
		social("google", fake.idToken(sub, sub + "@gmail.com", unverified)).andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
		social("google", fake.idToken(sub, null, Map.of())).andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));

		assertThat(socialAccounts.findByProviderAndProviderUserIdAndDeletedAtIsNull(SocialProvider.GOOGLE, sub))
			.isEmpty();
	}

	@Test
	void 그_이메일로_이미_가입된_계정이_있으면_409_ACCOUNT_EXISTS이고_새로_만들지_않는다() throws Exception {
		String email = newId() + "@gmail.com";
		users.saveAndFlush(User.withPassword(email, "hash", OffsetDateTime.now()));
		String sub = newId();

		social("google", fake.idToken(sub, email.toUpperCase(), Map.of())).andExpect(status().isConflict())
			.andExpect(jsonPath("$.code").value("ACCOUNT_EXISTS"));
		assertThat(socialAccounts.findByProviderAndProviderUserIdAndDeletedAtIsNull(SocialProvider.GOOGLE, sub))
			.isEmpty();
	}

	@Test
	void 다른_소셜로_가입한_이메일이어도_409다() throws Exception {
		String email = newId() + "@gmail.com";
		fake.naverProfiles.put("naver-token", FakeSocialProviders.naverProfile(newId(), email));
		social("naver", "naver-token").andExpect(status().isOk());

		social("google", fake.idToken(newId(), email, Map.of())).andExpect(status().isConflict())
			.andExpect(jsonPath("$.code").value("ACCOUNT_EXISTS"));
	}

	@Test
	void 탈퇴한_계정의_소셜_계정과_이메일로는_다시_가입할_수_있다() throws Exception {
		String sub = newId();
		String email = sub + "@gmail.com";
		social("google", fake.idToken(sub, email, Map.of())).andExpect(status().isOk());
		long oldId = users.findByEmailAndDeletedAtIsNull(email).orElseThrow().getId();
		me.withdraw(oldId);

		social("google", fake.idToken(sub, email, Map.of())).andExpect(status().isOk())
			.andExpect(jsonPath("$.isNewUser").value(true));
		assertThat(users.findByEmailAndDeletedAtIsNull(email).orElseThrow().getId()).isNotEqualTo(oldId);
	}

	// ── 네이버 로그인 ──

	@Test
	void 네이버로_처음_로그인하면_200이고_네이버_id로_계정을_찾는다() throws Exception {
		String id = newId();
		fake.naverProfiles.put("naver-1", FakeSocialProviders.naverProfile(id, id + "@example.com"));

		social("naver", "naver-1").andExpect(status().isOk()).andExpect(jsonPath("$.isNewUser").value(true));
		assertThat(fake.naverAuthHeaders).containsExactly("Bearer naver-1");

		// 연락처 이메일을 바꿔도 id가 같으면 같은 회원이다.
		fake.naverProfiles.put("naver-2", FakeSocialProviders.naverProfile(id, "new-" + id + "@example.com"));
		social("naver", "naver-2").andExpect(status().isOk()).andExpect(jsonPath("$.isNewUser").value(false));
	}

	@Test
	void 네이버가_401이거나_resultcode가_00이_아니면_401_INVALID_TOKEN이다() throws Exception {
		social("naver", "unknown-token").andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));

		fake.naverProfiles.put("odd", "{\"resultcode\":\"024\",\"message\":\"fail\"}");
		social("naver", "odd").andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
	}

	@Test
	void 네이버가_이메일을_주지_않으면_401이고_가입되지_않는다() throws Exception {
		String id = newId();
		fake.naverProfiles.put("no-email", FakeSocialProviders.naverProfile(id, null));

		social("naver", "no-email").andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
		assertThat(socialAccounts.findByProviderAndProviderUserIdAndDeletedAtIsNull(SocialProvider.NAVER, id))
			.isEmpty();
	}

	@Test
	void 네이버_서버가_아프면_500_INTERNAL_ERROR다() throws Exception {
		fake.naverStatus.set(503);

		social("naver", "any").andExpect(status().isInternalServerError())
			.andExpect(jsonPath("$.code").value("INTERNAL_ERROR"));
	}

	@Test
	void 헤더에_넣을_수_없는_글자가_든_네이버_토큰은_네이버에_보내지_않고_401이다() throws Exception {
		social("naver", "abc\r\nX-Evil: 1").andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
		assertThat(fake.naverAuthHeaders).isEmpty();
	}

	// ── 공통 입력 ──

	@Test
	void 지원하지_않는_provider는_400_INVALID_REQUEST와_provider_칸이다() throws Exception {
		for (String provider : new String[] { "kakao", "GOOGLE", "apple" }) {
			social(provider, "token").andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
				.andExpect(jsonPath("$.field").value("provider"));
		}
	}

	@Test
	void providerToken이_없거나_비면_400_INVALID_REQUEST다() throws Exception {
		mvc.perform(post("/auth/social/google").contentType(MediaType.APPLICATION_JSON).content("{}"))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
			.andExpect(jsonPath("$.field").value("providerToken"));
		social("google", " ").andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.field").value("providerToken"));
	}

	// ── 계정 연결 ──

	@Test
	void 내_계정에_네이버를_연결하면_200과_linkedProviders이고_그다음부터_네이버로_로그인된다() throws Exception {
		User user = emailUser();
		String id = newId();
		fake.naverProfiles.put("link-1", FakeSocialProviders.naverProfile(id, "other-" + id + "@example.com"));

		link(user, "naver", "link-1").andExpect(status().isOk())
			.andExpect(jsonPath("$.linkedProviders.length()").value(1))
			.andExpect(jsonPath("$.linkedProviders[0]").value("NAVER"));

		// 연결은 이메일을 보지 않는다. 네이버 이메일이 달라도 이 계정으로 들어간다.
		String body = social("naver", "link-1").andExpect(status().isOk())
			.andExpect(jsonPath("$.isNewUser").value(false))
			.andReturn()
			.getResponse()
			.getContentAsString();
		mvc.perform(get("/auth/me").header("Authorization", "Bearer " + JsonPath.read(body, "$.accessToken")))
			.andExpect(jsonPath("$.email").value(user.getEmail()));
	}

	@Test
	void 같은_소셜_계정을_다시_연결하면_200으로_그대로다() throws Exception {
		User user = emailUser();
		String sub = newId();
		String token = fake.idToken(sub, sub + "@gmail.com", Map.of());
		link(user, "google", token).andExpect(status().isOk());

		link(user, "google", token).andExpect(status().isOk())
			.andExpect(jsonPath("$.linkedProviders.length()").value(1))
			.andExpect(jsonPath("$.linkedProviders[0]").value("GOOGLE"));
	}

	@Test
	void 다른_계정에_붙은_소셜_계정은_409_SOCIAL_ALREADY_LINKED다() throws Exception {
		String sub = newId();
		social("google", fake.idToken(sub, sub + "@gmail.com", Map.of())).andExpect(status().isOk());

		link(emailUser(), "google", fake.idToken(sub, sub + "@gmail.com", Map.of())).andExpect(status().isConflict())
			.andExpect(jsonPath("$.code").value("SOCIAL_ALREADY_LINKED"));
	}

	@Test
	void 내_계정에_같은_회사의_다른_계정이_붙어_있으면_409다() throws Exception {
		User user = emailUser();
		link(user, "google", fake.idToken(newId(), "a@gmail.com", Map.of())).andExpect(status().isOk());

		link(user, "google", fake.idToken(newId(), "b@gmail.com", Map.of())).andExpect(status().isConflict())
			.andExpect(jsonPath("$.code").value("SOCIAL_ALREADY_LINKED"));
	}

	@Test
	void 탈퇴한_계정에_붙어_있던_소셜_계정은_다시_연결할_수_있다() throws Exception {
		User old = emailUser();
		String sub = newId();
		link(old, "google", fake.idToken(sub, sub + "@gmail.com", Map.of())).andExpect(status().isOk());
		me.withdraw(old.getId());

		link(emailUser(), "google", fake.idToken(sub, sub + "@gmail.com", Map.of())).andExpect(status().isOk())
			.andExpect(jsonPath("$.linkedProviders[0]").value("GOOGLE"));
	}

	@Test
	void 연결할_때_소셜_토큰이_틀리면_401_INVALID_TOKEN이다() throws Exception {
		link(emailUser(), "naver", "unknown-token").andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
	}

	@Test
	void 연결은_구글_이메일이_인증되지_않았어도_된다() throws Exception {
		Map<String, Object> unverified = new HashMap<>();
		unverified.put("email_verified", false);

		link(emailUser(), "google", fake.idToken(newId(), null, unverified)).andExpect(status().isOk());
	}

	@Test
	void 연결은_액세스_토큰이_없거나_탈퇴한_회원이면_401이고_회사를_부르지_않는다() throws Exception {
		mvc.perform(post("/auth/me/social/naver").contentType(MediaType.APPLICATION_JSON)
			.content("{\"providerToken\":\"t\"}")).andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));

		User user = emailUser();
		String access = tokens.issue(user.getId()).accessToken();
		me.withdraw(user.getId());
		mvc.perform(post("/auth/me/social/naver").header("Authorization", "Bearer " + access)
			.contentType(MediaType.APPLICATION_JSON)
			.content("{\"providerToken\":\"t\"}")).andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
		assertThat(fake.naverAuthHeaders).isEmpty();
	}

	@Test
	void 연결의_지원하지_않는_provider는_400이다() throws Exception {
		link(emailUser(), "kakao", "token").andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.field").value("provider"));
	}

	// ── 연동 해제 ──

	@Test
	void 연동을_해제하면_200과_남은_linkedProviders이고_그_소셜로는_더_이_계정에_들어오지_않는다() throws Exception {
		User user = emailUser();
		String sub = newId();
		link(user, "google", fake.idToken(sub, sub + "@gmail.com", Map.of())).andExpect(status().isOk());
		String id = newId();
		fake.naverProfiles.put("unlink-n", FakeSocialProviders.naverProfile(id, id + "@example.com"));
		link(user, "naver", "unlink-n").andExpect(status().isOk());

		unlink(user, "google").andExpect(status().isOk())
			.andExpect(jsonPath("$.linkedProviders.length()").value(1))
			.andExpect(jsonPath("$.linkedProviders[0]").value("NAVER"));
		assertThat(socialAccounts.findByProviderAndProviderUserIdAndDeletedAtIsNull(SocialProvider.GOOGLE, sub))
			.isEmpty();

		// 끊은 구글 계정으로 로그인하면 이 계정이 아니라 새 계정이 생긴다.
		social("google", fake.idToken(sub, sub + "@gmail.com", Map.of())).andExpect(status().isOk())
			.andExpect(jsonPath("$.isNewUser").value(true));
	}

	@Test
	void 연동돼_있지_않은_회사를_해제하면_200으로_그대로다() throws Exception {
		unlink(emailUser(), "naver").andExpect(status().isOk())
			.andExpect(jsonPath("$.linkedProviders.length()").value(0));
	}

	@Test
	void 비밀번호가_없는_회원의_마지막_소셜_연결은_409_LAST_LOGIN_METHOD이고_끊지_않는다() throws Exception {
		String id = newId();
		fake.naverProfiles.put("only-n", FakeSocialProviders.naverProfile(id, id + "@example.com"));
		social("naver", "only-n").andExpect(status().isOk());
		User user = users.findByEmailAndDeletedAtIsNull(id + "@example.com").orElseThrow();

		unlink(user, "naver").andExpect(status().isConflict())
			.andExpect(jsonPath("$.code").value("LAST_LOGIN_METHOD"));
		assertThat(socialAccounts.findByProviderAndProviderUserIdAndDeletedAtIsNull(SocialProvider.NAVER, id))
			.isPresent();
	}

	@Test
	void 비밀번호가_없어도_다른_소셜이_남으면_끊을_수_있다() throws Exception {
		String id = newId();
		fake.naverProfiles.put("two-n", FakeSocialProviders.naverProfile(id, id + "@example.com"));
		social("naver", "two-n").andExpect(status().isOk());
		User user = users.findByEmailAndDeletedAtIsNull(id + "@example.com").orElseThrow();
		link(user, "google", fake.idToken(newId(), "x@gmail.com", Map.of())).andExpect(status().isOk());

		unlink(user, "naver").andExpect(status().isOk())
			.andExpect(jsonPath("$.linkedProviders[0]").value("GOOGLE"));
		// 남은 구글은 마지막 수단이라 막힌다.
		unlink(user, "google").andExpect(status().isConflict())
			.andExpect(jsonPath("$.code").value("LAST_LOGIN_METHOD"));
	}

	@Test
	void 비밀번호가_있으면_마지막_소셜_연결도_끊을_수_있다() throws Exception {
		User user = emailUser();
		link(user, "google", fake.idToken(newId(), "y@gmail.com", Map.of())).andExpect(status().isOk());

		unlink(user, "google").andExpect(status().isOk())
			.andExpect(jsonPath("$.linkedProviders.length()").value(0));
	}

	@Test
	void 해제는_액세스_토큰이_없으면_401이고_모르는_provider는_400이다() throws Exception {
		mvc.perform(delete("/auth/me/social/google")).andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
		unlink(emailUser(), "kakao").andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.field").value("provider"));
	}

	private ResultActions unlink(User user, String provider) throws Exception {
		return mvc.perform(delete("/auth/me/social/" + provider)
			.header("Authorization", "Bearer " + tokens.issue(user.getId()).accessToken()));
	}

	private ResultActions social(String provider, String providerToken) throws Exception {
		return mvc.perform(post("/auth/social/" + provider).contentType(MediaType.APPLICATION_JSON)
			.content("{\"providerToken\":" + json(providerToken) + "}"));
	}

	private ResultActions link(User user, String provider, String providerToken) throws Exception {
		return mvc.perform(post("/auth/me/social/" + provider)
			.header("Authorization", "Bearer " + tokens.issue(user.getId()).accessToken())
			.contentType(MediaType.APPLICATION_JSON)
			.content("{\"providerToken\":" + json(providerToken) + "}"));
	}

	private User emailUser() {
		return users.saveAndFlush(User.withPassword(newId() + "@example.com", "hash", OffsetDateTime.now()));
	}

	private static String json(String value) {
		return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "\\r").replace("\n", "\\n")
				+ "\"";
	}

	private static String newId() {
		return "u" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
	}

}
