package com.lolog.auth.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.lolog.auth.MutableClock;
import com.lolog.auth.SignupCodes;
import com.lolog.auth.TestContainers;
import com.lolog.auth.email.EmailCodeStore;
import com.lolog.auth.token.SuspendedUsers;
import com.lolog.auth.token.TokenService;
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
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

// 관리자 계정 정지와 정지 풀기(LOLog-docs PR #59 spec/admin.md 2장). lolog-api는 가짜 서버로 대신한다.
// Docker가 켜져 있어야 한다.
@SpringBootTest
@AutoConfigureMockMvc
@Import({ TestContainers.class, MutableClock.Config.class })
class AdminSuspensionApiTests {

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
	TokenService tokens;

	@Autowired
	EmailCodeStore codes;

	@Autowired
	JdbcTemplate jdbc;

	@Autowired
	StringRedisTemplate redis;

	@Autowired
	SuspensionNotifier notifier;

	@Autowired
	MutableClock clock;

	@BeforeEach
	void reset() {
		clock.reset();
		api.reset();
		// 다른 테스트가 남긴 "다시 알릴 회원"을 정리해, 요청 기록에 섞이지 않게 한다.
		notifier.retryPending();
		api.reset();
	}

	@Test
	void 정지하면_204이고_기한과_이유를_적고_lolog_api에_알린다() throws Exception {
		User target = newUser();
		OffsetDateTime before = OffsetDateTime.now(clock);

		suspend(adminToken(), target.getId(), "MONTH_3", "  도배  ").andExpect(status().isNoContent());

		User saved = users.findById(target.getId()).orElseThrow();
		assertThat(saved.getSuspendedAt()).isNotNull();
		assertThat(saved.getSuspendedUntil().toInstant()).isEqualTo(saved.getSuspendedAt().plusMonths(3).toInstant());
		assertThat(saved.getSuspendedAt().toInstant()).isAfterOrEqualTo(before.toInstant().minusSeconds(1));
		assertThat(saved.getSuspendedReason()).isEqualTo("도배");
		assertThat(saved.isSuspensionNotifyPending()).isFalse();
		assertThat(api.requestsFor(target.getId())).hasSize(1);
		String request = api.requestsFor(target.getId()).get(0);
		assertThat(request).startsWith("PUT /internal/users/" + target.getId() + "/suspension internal-test-token ");
		String until = JsonPath.read(request.substring(request.indexOf('{')), "$.suspendedUntil");
		assertThat(OffsetDateTime.parse(until).toInstant()).isEqualTo(saved.getSuspendedUntil().toInstant());
	}

	@Test
	void 영구_정지는_기한이_없고_suspendedUntil_null로_알린다() throws Exception {
		User target = newUser();

		suspend(adminToken(), target.getId(), "PERMANENT", "욕설").andExpect(status().isNoContent());

		assertThat(users.findById(target.getId()).orElseThrow().getSuspendedUntil()).isNull();
		assertThat(api.requestsFor(target.getId()))
			.containsExactly("PUT /internal/users/" + target.getId() + "/suspension internal-test-token {\"suspendedUntil\":null}");
	}

	@Test
	void 정지된_계정은_이메일_로그인과_갱신이_403_ACCOUNT_SUSPENDED이고_전에_받은_토큰은_못_쓴다() throws Exception {
		String email = newEmail();
		String signup = signup(email);
		long userId = users.findByEmailAndDeletedAtIsNull(email).orElseThrow().getId();
		String access = JsonPath.read(signup, "$.accessToken");
		String refresh = JsonPath.read(signup, "$.refreshToken");

		suspend(adminToken(), userId, "MONTH_1", "도배").andExpect(status().isNoContent());

		login(email, "password1").andExpect(status().isForbidden())
			.andExpect(jsonPath("$.code").value("ACCOUNT_SUSPENDED"));
		// 비밀번호가 틀리면 정지 여부를 알리지 않는다.
		login(email, "wrong-pass1").andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
		// 정지할 때 리프레시 토큰을 모두 지웠다.
		refresh(refresh).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
		// 정지 전에 받은 액세스 토큰은 /auth에서 401 INVALID_TOKEN이다.
		mvc.perform(get("/auth/me").header("Authorization", "Bearer " + access))
			.andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
		assertThat(redis.getExpire(SuspendedUsers.KEY + userId)).isBetween(30L * 60, 31L * 60);
	}

	@Test
	void 갱신_도중_정지되면_갱신도_403_ACCOUNT_SUSPENDED다() throws Exception {
		String email = newEmail();
		String refresh = JsonPath.read(signup(email), "$.refreshToken");
		long userId = users.findByEmailAndDeletedAtIsNull(email).orElseThrow().getId();
		// 리프레시 토큰은 남아 있는데 DB만 정지된 경우(정지 직후 Redis 정리 전 등)
		jdbc.update("UPDATE users SET suspended_at = now() WHERE id = ?", userId);

		refresh(refresh).andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("ACCOUNT_SUSPENDED"));
	}

	@Test
	void 기한이_지나면_저절로_풀려_로그인된다() throws Exception {
		String email = newEmail();
		signup(email);
		long userId = users.findByEmailAndDeletedAtIsNull(email).orElseThrow().getId();
		suspend(adminToken(), userId, "MONTH_1", "도배").andExpect(status().isNoContent());

		// 1개월은 달력으로 센다(28~31일). 어느 달이든 28일 뒤에는 아직 정지, 32일 뒤에는 풀려 있다.
		clock.advance(Duration.ofDays(28));
		login(email, "password1").andExpect(status().isForbidden());

		clock.advance(Duration.ofDays(4));
		login(email, "password1").andExpect(status().isOk());
	}

	@Test
	void 정지를_풀면_204이고_기록과_키를_지우고_lolog_api에_알린다() throws Exception {
		String email = newEmail();
		signup(email);
		long userId = users.findByEmailAndDeletedAtIsNull(email).orElseThrow().getId();
		String admin = adminToken();
		suspend(admin, userId, "PERMANENT", "욕설").andExpect(status().isNoContent());
		api.reset();

		unsuspend(admin, userId).andExpect(status().isNoContent());

		User saved = users.findById(userId).orElseThrow();
		assertThat(saved.getSuspendedAt()).isNull();
		assertThat(saved.getSuspendedUntil()).isNull();
		assertThat(saved.getSuspendedReason()).isNull();
		assertThat(redis.hasKey(SuspendedUsers.KEY + userId)).isFalse();
		assertThat(api.requestsFor(userId))
			.containsExactly("DELETE /internal/users/" + userId + "/suspension internal-test-token");
		login(email, "password1").andExpect(status().isOk());
	}

	@Test
	void 정지되지_않은_계정을_풀어도_204이고_알리지_않는다() throws Exception {
		User target = newUser();

		unsuspend(adminToken(), target.getId()).andExpect(status().isNoContent());

		assertThat(api.requestsFor(target.getId())).isEmpty();
	}

	@Test
	void 이미_정지된_계정을_다시_정지하면_새_기한과_이유로_바꾼다() throws Exception {
		User target = newUser();
		suspend(adminToken(), target.getId(), "PERMANENT", "욕설").andExpect(status().isNoContent());

		clock.advance(Duration.ofDays(1));
		suspend(adminToken(), target.getId(), "MONTH_1", "줄여 줌").andExpect(status().isNoContent());

		User saved = users.findById(target.getId()).orElseThrow();
		assertThat(saved.getSuspendedUntil()).isNotNull();
		assertThat(saved.getSuspendedReason()).isEqualTo("줄여 줌");
		assertThat(api.requestsFor(target.getId())).hasSize(2);
	}

	@Test
	void lolog_api가_실패해도_204이고_204가_올_때까지_다시_알린다() throws Exception {
		User target = newUser();
		api.status.set(500);

		suspend(adminToken(), target.getId(), "MONTH_6", "도배").andExpect(status().isNoContent());
		assertThat(users.findById(target.getId()).orElseThrow().isSuspensionNotifyPending()).isTrue();

		notifier.retryPending();
		assertThat(users.findById(target.getId()).orElseThrow().isSuspensionNotifyPending()).isTrue();

		api.status.set(204);
		notifier.retryPending();
		assertThat(users.findById(target.getId()).orElseThrow().isSuspensionNotifyPending()).isFalse();
		assertThat(api.requestsFor(target.getId())).hasSize(3).allMatch(r -> r.startsWith("PUT "));
	}

	@Test
	void 알리지_못한_채_정지를_풀면_다시_알릴_때는_해제만_알린다() throws Exception {
		User target = newUser();
		String admin = adminToken();
		api.status.set(500);
		suspend(admin, target.getId(), "MONTH_1", "도배").andExpect(status().isNoContent());
		unsuspend(admin, target.getId()).andExpect(status().isNoContent());
		api.reset();

		notifier.retryPending();

		assertThat(api.requestsFor(target.getId()))
			.containsExactly("DELETE /internal/users/" + target.getId() + "/suspension internal-test-token");
		assertThat(users.findById(target.getId()).orElseThrow().isSuspensionNotifyPending()).isFalse();
	}

	@Test
	void 관리자는_자신과_다른_관리자를_정지할_수_없다() throws Exception {
		User admin = newAdmin();
		User other = newAdmin();
		String access = tokens.issue(admin.getId()).accessToken();

		suspend(access, admin.getId(), "MONTH_1", "시험").andExpect(status().isForbidden())
			.andExpect(jsonPath("$.code").value("FORBIDDEN"));
		suspend(access, other.getId(), "MONTH_1", "시험").andExpect(status().isForbidden());
		assertThat(users.findById(other.getId()).orElseThrow().getSuspendedAt()).isNull();
	}

	@Test
	void 없거나_탈퇴한_회원은_404_USER_NOT_FOUND다() throws Exception {
		User gone = newUser();
		gone.delete(OffsetDateTime.now());
		users.saveAndFlush(gone);
		String admin = adminToken();

		for (long id : new long[] { gone.getId(), Long.MAX_VALUE }) {
			suspend(admin, id, "MONTH_1", "시험").andExpect(status().isNotFound())
				.andExpect(jsonPath("$.code").value("USER_NOT_FOUND"));
			unsuspend(admin, id).andExpect(status().isNotFound());
		}
	}

	@Test
	void 관리자가_아니면_403이고_토큰이_없으면_401이다() throws Exception {
		User user = newUser();
		User target = newUser();

		suspend(tokens.issue(user.getId()).accessToken(), target.getId(), "MONTH_1", "시험")
			.andExpect(status().isForbidden());
		unsuspend(tokens.issue(user.getId()).accessToken(), target.getId()).andExpect(status().isForbidden());
		mvc.perform(post("/auth/admin/users/" + target.getId() + "/suspend").contentType(MediaType.APPLICATION_JSON)
			.content("{\"duration\":\"MONTH_1\",\"reason\":\"시험\"}")).andExpect(status().isUnauthorized());
		assertThat(users.findById(target.getId()).orElseThrow().getSuspendedAt()).isNull();
	}

	@Test
	void 틀린_duration과_reason은_400이고_field로_알린다() throws Exception {
		User target = newUser();
		String admin = adminToken();
		String[][] cases = { { "\"MONTH_2\"", "\"이유\"", "duration" }, { "\"month_1\"", "\"이유\"", "duration" },
				{ "null", "\"이유\"", "duration" }, { "\"MONTH_1\"", "\"   \"", "reason" },
				{ "\"MONTH_1\"", "null", "reason" }, { "\"MONTH_1\"", "\"" + "가".repeat(201) + "\"", "reason" } };
		for (String[] c : cases) {
			mvc.perform(post("/auth/admin/users/" + target.getId() + "/suspend")
				.header("Authorization", "Bearer " + admin)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"duration\":" + c[0] + ",\"reason\":" + c[1] + "}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
				.andExpect(jsonPath("$.field").value(c[2]));
		}
		// 200자는 된다.
		suspend(admin, target.getId(), "MONTH_1", "가".repeat(200)).andExpect(status().isNoContent());
	}

	private ResultActions suspend(String access, long userId, String duration, String reason) throws Exception {
		return mvc.perform(post("/auth/admin/users/" + userId + "/suspend").header("Authorization", "Bearer " + access)
			.contentType(MediaType.APPLICATION_JSON)
			.content("{\"duration\":\"" + duration + "\",\"reason\":\"" + reason + "\"}"));
	}

	private ResultActions unsuspend(String access, long userId) throws Exception {
		return mvc.perform(delete("/auth/admin/users/" + userId + "/suspend").header("Authorization", "Bearer " + access));
	}

	private ResultActions login(String email, String password) throws Exception {
		return mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
			.content("{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}"));
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

	private User newUser() {
		return users.saveAndFlush(User.social(newEmail(), OffsetDateTime.now()));
	}

	// 관리자는 DB에서 role을 직접 바꿔 정한다(spec/admin.md 1장).
	private User newAdmin() {
		User user = newUser();
		jdbc.update("UPDATE users SET role = 'ADMIN' WHERE id = ?", user.getId());
		return users.findById(user.getId()).orElseThrow();
	}

	private static String newEmail() {
		return "u" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
	}

}
