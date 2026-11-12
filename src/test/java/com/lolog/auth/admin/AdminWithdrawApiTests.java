package com.lolog.auth.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.lolog.auth.SignupCodes;
import com.lolog.auth.TestContainers;
import com.lolog.auth.email.EmailCodeStore;
import com.lolog.auth.me.UserDataDeleter;
import com.lolog.auth.token.TokenService;
import com.lolog.auth.token.WithdrawnUsers;
import com.lolog.auth.user.BannedIdentity;
import com.lolog.auth.user.BannedIdentityRepository;
import com.lolog.auth.user.SocialAccount;
import com.lolog.auth.user.SocialAccountRepository;
import com.lolog.auth.user.SocialProvider;
import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import java.io.IOException;
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
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

// 관리자가 탈퇴시키기와 다시 가입 막기(LOLog-docs PR #59 spec/admin.md 3장). lolog-api는 가짜 서버로 대신한다.
// 소셜 로그인·연결에서 막히는 것은 SocialAuthApiTests에 있다. Docker가 켜져 있어야 한다.
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestContainers.class)
class AdminWithdrawApiTests {

	static final FakeSuspensionApi api;

	static {
		try {
			api = new FakeSuspensionApi();
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
	BannedIdentityRepository bannedIdentities;

	@Autowired
	TokenService tokens;

	@Autowired
	EmailCodeStore codes;

	@Autowired
	JdbcTemplate jdbc;

	@Autowired
	StringRedisTemplate redis;

	@Autowired
	UserDataDeleter deleter;

	@BeforeEach
	void reset() {
		api.reset();
		// 다른 테스트가 남긴 "다시 부를 회원"을 정리해, 요청 기록에 섞이지 않게 한다.
		deleter.retryPending();
		api.reset();
	}

	@Test
	void 탈퇴시키면_204이고_본인_탈퇴와_같이_지우고_lolog_api_데이터_삭제를_부른다() throws Exception {
		String email = newEmail();
		String signup = signup(email);
		long userId = users.findByEmailAndDeletedAtIsNull(email).orElseThrow().getId();
		socialAccounts.saveAndFlush(new SocialAccount(userId, SocialProvider.NAVER, "n-" + userId, OffsetDateTime.now()));

		withdraw(adminToken(), userId).andExpect(status().isNoContent());

		User saved = users.findById(userId).orElseThrow();
		assertThat(saved.getDeletedAt()).isNotNull();
		assertThat(saved.getDataDeletedAt()).isNotNull();
		assertThat(socialAccounts.findByUserIdAndDeletedAtIsNull(userId)).isEmpty();
		assertThat(redis.hasKey(WithdrawnUsers.KEY + userId)).isTrue();
		assertThat(api.requests).contains("DELETE /internal/users/" + userId + " internal-test-token");
		// 리프레시 토큰은 모두 지웠고, 남은 액세스 토큰은 /auth에서 401이다.
		refresh(JsonPath.read(signup, "$.refreshToken")).andExpect(status().isUnauthorized());
		mvc.perform(get("/auth/me").header("Authorization", "Bearer " + JsonPath.read(signup, "$.accessToken")))
			.andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
	}

	@Test
	void 탈퇴시키면_그_이메일과_연결된_소셜_계정을_적어_둔다() throws Exception {
		User target = users.saveAndFlush(User.social(newEmail(), OffsetDateTime.now()));
		long id = target.getId();
		socialAccounts.saveAndFlush(new SocialAccount(id, SocialProvider.GOOGLE, "g-" + id, OffsetDateTime.now()));
		socialAccounts.saveAndFlush(new SocialAccount(id, SocialProvider.NAVER, "n-" + id, OffsetDateTime.now()));

		withdraw(adminToken(), id).andExpect(status().isNoContent());

		assertThat(bannedIdentities.findAll()).filteredOn(b -> b.getUserId() == id)
			.extracting(b -> b.getKind() + ":" + b.getValue())
			.containsExactlyInAnyOrder("EMAIL:" + target.getEmail(), "GOOGLE:g-" + id, "NAVER:n-" + id);
	}

	@Test
	void 탈퇴시킨_계정의_이메일로는_다시_가입하면_409_ACCOUNT_BANNED다() throws Exception {
		String email = newEmail();
		signup(email);
		long userId = users.findByEmailAndDeletedAtIsNull(email).orElseThrow().getId();
		withdraw(adminToken(), userId).andExpect(status().isNoContent());

		// 대문자로 써도 같은 이메일이다.
		mvc.perform(post("/auth/signup").contentType(MediaType.APPLICATION_JSON)
			.content(SignupCodes.signupJson(codes, email.toUpperCase(), "password1")))
			.andExpect(status().isConflict())
			.andExpect(jsonPath("$.code").value("ACCOUNT_BANNED"));
		// 인증번호가 틀리면 막힌 이메일인지 알리지 않는다(번호를 먼저 본다).
		codes.save(email, SignupCodes.CODE);
		mvc.perform(post("/auth/signup").contentType(MediaType.APPLICATION_JSON)
			.content("{\"email\":\"" + email + "\",\"password\":\"password1\",\"code\":\"000000\"}"))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.code").value("INVALID_CODE"));
		assertThat(users.findByEmailAndDeletedAtIsNull(email)).isEmpty();
	}

	@Test
	void 본인이_탈퇴한_계정의_이메일로는_지금처럼_다시_가입된다() throws Exception {
		String email = newEmail();
		String access = JsonPath.read(signup(email), "$.accessToken");
		mvc.perform(delete("/auth/me").header("Authorization", "Bearer " + access)).andExpect(status().isNoContent());

		signup(email);
		assertThat(bannedIdentities.isEmailBanned(email)).isFalse();
	}

	@Test
	void lolog_api가_실패해도_204이고_데이터_삭제는_뒤에서_다시_부른다() throws Exception {
		User target = users.saveAndFlush(User.social(newEmail(), OffsetDateTime.now()));
		api.status.set(500);

		withdraw(adminToken(), target.getId()).andExpect(status().isNoContent());
		assertThat(users.findById(target.getId()).orElseThrow().getDataDeletedAt()).isNull();

		api.status.set(204);
		deleter.retryPending();
		assertThat(users.findById(target.getId()).orElseThrow().getDataDeletedAt()).isNotNull();
	}

	@Test
	void 관리자는_자신과_다른_관리자를_탈퇴시킬_수_없다() throws Exception {
		User admin = newAdmin();
		User other = newAdmin();
		String access = tokens.issue(admin.getId()).accessToken();

		withdraw(access, admin.getId()).andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("FORBIDDEN"));
		withdraw(access, other.getId()).andExpect(status().isForbidden());
		assertThat(users.findById(other.getId()).orElseThrow().getDeletedAt()).isNull();
		assertThat(bannedIdentities.isEmailBanned(other.getEmail())).isFalse();
	}

	@Test
	void 없거나_이미_탈퇴한_회원은_404_USER_NOT_FOUND다() throws Exception {
		User gone = users.saveAndFlush(User.social(newEmail(), OffsetDateTime.now()));
		gone.delete(OffsetDateTime.now());
		users.saveAndFlush(gone);
		String admin = adminToken();

		withdraw(admin, gone.getId()).andExpect(status().isNotFound()).andExpect(jsonPath("$.code").value("USER_NOT_FOUND"));
		withdraw(admin, Long.MAX_VALUE).andExpect(status().isNotFound());
		// 본인이 탈퇴한 계정을 나중에 막을 수는 없다.
		assertThat(bannedIdentities.isEmailBanned(gone.getEmail())).isFalse();
	}

	@Test
	void 관리자가_아니면_403이고_토큰이_없으면_401이다() throws Exception {
		User user = users.saveAndFlush(User.social(newEmail(), OffsetDateTime.now()));
		User target = users.saveAndFlush(User.social(newEmail(), OffsetDateTime.now()));

		withdraw(tokens.issue(user.getId()).accessToken(), target.getId()).andExpect(status().isForbidden());
		mvc.perform(delete("/auth/admin/users/" + target.getId())).andExpect(status().isUnauthorized());
		assertThat(users.findById(target.getId()).orElseThrow().getDeletedAt()).isNull();
	}

	@Test
	void 같은_값이_이미_적혀_있어도_탈퇴시킬_수_있다() throws Exception {
		User target = users.saveAndFlush(User.social(newEmail(), OffsetDateTime.now()));
		bannedIdentities.saveAndFlush(
				new BannedIdentity(BannedIdentity.Kind.EMAIL, target.getEmail(), target.getId(), OffsetDateTime.now()));

		withdraw(adminToken(), target.getId()).andExpect(status().isNoContent());
		assertThat(bannedIdentities.findAll()).filteredOn(b -> b.getValue().equals(target.getEmail())).hasSize(1);
	}

	private ResultActions withdraw(String access, long userId) throws Exception {
		return mvc.perform(delete("/auth/admin/users/" + userId).header("Authorization", "Bearer " + access));
	}

	private ResultActions refresh(String refreshToken) throws Exception {
		return mvc.perform(post("/auth/refresh").contentType(MediaType.APPLICATION_JSON)
			.content("{\"refreshToken\":\"" + refreshToken + "\"}"));
	}

	private String signup(String email) throws Exception {
		return mvc
			.perform(post("/auth/signup").contentType(MediaType.APPLICATION_JSON)
				.content(SignupCodes.signupJson(codes, email, "password1")))
			.andExpect(status().isCreated())
			.andReturn()
			.getResponse()
			.getContentAsString();
	}

	private String adminToken() {
		return tokens.issue(newAdmin().getId()).accessToken();
	}

	// 관리자는 DB에서 role을 직접 바꿔 정한다(spec/admin.md 1장).
	private User newAdmin() {
		User user = users.saveAndFlush(User.social(newEmail(), OffsetDateTime.now()));
		jdbc.update("UPDATE users SET role = 'ADMIN' WHERE id = ?", user.getId());
		return users.findById(user.getId()).orElseThrow();
	}

	private static String newEmail() {
		return "u" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
	}

}
