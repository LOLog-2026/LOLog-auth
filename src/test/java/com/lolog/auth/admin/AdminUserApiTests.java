package com.lolog.auth.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.lolog.auth.MutableClock;
import com.lolog.auth.TestContainers;
import com.lolog.auth.token.AccessTokens;
import com.lolog.auth.token.TokenService;
import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

// 관리자 구분과 계정 목록(LOLog-docs PR #59 spec/admin.md 1장·6장). Docker가 켜져 있어야 한다.
// 다른 테스트가 만든 회원과 섞이지 않게, 목록은 테스트마다 다른 이메일 머리말(q)로 찾는다.
@SpringBootTest
@AutoConfigureMockMvc
@Import({ TestContainers.class, MutableClock.Config.class })
class AdminUserApiTests {

	@Autowired
	MockMvc mvc;

	@Autowired
	UserRepository users;

	@Autowired
	TokenService tokens;

	@Autowired
	JdbcTemplate jdbc;

	@Autowired
	MutableClock clock;

	@BeforeEach
	void resetClock() {
		clock.reset();
	}

	@Test
	void 관리자_토큰에는_role_ADMIN이_들어가고_내_정보에도_보인다() throws Exception {
		User admin = newAdmin();
		String access = tokens.issue(admin.getId()).accessToken();

		assertThat(AccessTokens.verify(access, AccessTokens.SECRET).getStringClaim("role")).isEqualTo("ADMIN");
		mvc.perform(get("/auth/me").header("Authorization", "Bearer " + access))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.role").value("ADMIN"));
	}

	@Test
	void 보통_회원의_토큰에는_role_USER가_들어간다() throws Exception {
		User user = users.saveAndFlush(User.social(newEmail("u"), OffsetDateTime.now()));

		String access = tokens.issue(user.getId()).accessToken();
		assertThat(AccessTokens.verify(access, AccessTokens.SECRET).getStringClaim("role")).isEqualTo("USER");
	}

	@Test
	void 관리자가_아니면_403_FORBIDDEN이다() throws Exception {
		User user = users.saveAndFlush(User.social(newEmail("u"), OffsetDateTime.now()));

		list(tokenOf(user), "").andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("FORBIDDEN"));
		// 요청 값이 틀려도 관리자 확인이 먼저다.
		list(tokenOf(user), "?sort=WRONG").andExpect(status().isForbidden());
	}

	@Test
	void 토큰이_없거나_틀리면_401_INVALID_TOKEN이다() throws Exception {
		mvc.perform(get("/auth/admin/users"))
			.andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
		list("broken", "").andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
	}

	@Test
	void 관리자에서_빼면_전에_받은_토큰으로도_바로_막힌다() throws Exception {
		User admin = newAdmin();
		String access = tokenOf(admin);
		jdbc.update("UPDATE users SET role = 'USER' WHERE id = ?", admin.getId());

		list(access, "").andExpect(status().isForbidden());
	}

	@Test
	void 탈퇴한_관리자의_토큰이면_401_INVALID_TOKEN이다() throws Exception {
		User admin = newAdmin();
		String access = tokenOf(admin);
		jdbc.update("UPDATE users SET deleted_at = now() WHERE id = ?", admin.getId());

		list(access, "").andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
	}

	@Test
	void 계정_목록은_기본으로_가입_최신순이고_항목_모양이_명세와_같다() throws Exception {
		String prefix = prefix();
		User first = users.saveAndFlush(User.withPassword(prefix + "a@example.com", "hash", OffsetDateTime.now()));
		User second = users.saveAndFlush(User.social(prefix + "b@example.com", OffsetDateTime.now()));

		list(tokenOf(newAdmin()), "?q=" + prefix).andExpect(status().isOk())
			.andExpect(jsonPath("$.users.length()").value(2))
			.andExpect(jsonPath("$.users[0].userId").value(second.getId()))
			.andExpect(jsonPath("$.users[1].userId").value(first.getId()))
			.andExpect(jsonPath("$.users[0].email").value(prefix + "b@example.com"))
			.andExpect(jsonPath("$.users[0].createdAt").isString())
			.andExpect(jsonPath("$.users[0].role").value("USER"))
			.andExpect(jsonPath("$.users[0].suspendedAt").isEmpty())
			.andExpect(jsonPath("$.users[0].suspendedUntil").isEmpty())
			.andExpect(jsonPath("$.users[0].suspendReason").isEmpty())
			.andExpect(jsonPath("$.nextCursor").isEmpty());
	}

	@Test
	void 오래된순과_이메일순으로_정렬한다() throws Exception {
		String prefix = prefix();
		User b = users.saveAndFlush(User.social(prefix + "b@example.com", OffsetDateTime.now()));
		User c = users.saveAndFlush(User.social(prefix + "c@example.com", OffsetDateTime.now()));
		User a = users.saveAndFlush(User.social(prefix + "a@example.com", OffsetDateTime.now()));
		String admin = tokenOf(newAdmin());

		assertThat(ids(admin, "?q=" + prefix + "&sort=OLDEST")).containsExactly(b.getId(), c.getId(), a.getId());
		assertThat(ids(admin, "?q=" + prefix + "&sort=EMAIL")).containsExactly(a.getId(), b.getId(), c.getId());
		assertThat(ids(admin, "?q=" + prefix + "&sort=NEWEST")).containsExactly(a.getId(), c.getId(), b.getId());
	}

	@Test
	void cursor로_다음_페이지를_받고_마지막_페이지는_nextCursor가_null이다() throws Exception {
		String prefix = prefix();
		List<Long> created = new ArrayList<>();
		for (int i = 0; i < 5; i++) {
			created.add(users.saveAndFlush(User.social(prefix + i + "@example.com", OffsetDateTime.now())).getId());
		}
		String admin = tokenOf(newAdmin());

		for (String sort : new String[] { "NEWEST", "OLDEST", "EMAIL" }) {
			List<Long> seen = new ArrayList<>();
			String cursor = null;
			int pages = 0;
			do {
				String query = "?q=" + prefix + "&sort=" + sort + "&size=2" + (cursor == null ? "" : "&cursor=" + cursor);
				String body = list(admin, query).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
				List<Number> pageIds = JsonPath.read(body, "$.users[*].userId");
				pageIds.forEach(id -> seen.add(id.longValue()));
				cursor = JsonPath.read(body, "$.nextCursor");
				pages++;
			}
			while (cursor != null);
			assertThat(pages).as(sort).isEqualTo(3);
			assertThat(seen).as(sort).containsExactlyInAnyOrderElementsOf(created).doesNotHaveDuplicates();
		}
	}

	@Test
	void 이메일_일부로_찾고_대소문자를_가리지_않으며_LIKE_특수문자는_글자_그대로_찾는다() throws Exception {
		String prefix = prefix();
		User plain = users.saveAndFlush(User.social(prefix + "abc@example.com", OffsetDateTime.now()));
		User underscore = users.saveAndFlush(User.social(prefix + "a_c@example.com", OffsetDateTime.now()));
		String admin = tokenOf(newAdmin());

		assertThat(ids(admin, "?q=" + prefix.toUpperCase() + "ABC")).containsExactly(plain.getId());
		// _는 아무 글자가 아니라 밑줄 그대로다.
		assertThat(ids(admin, "?q=" + prefix + "a_c")).containsExactly(underscore.getId());
		assertThat(ids(admin, "?q=" + prefix + "%")).isEmpty();
	}

	@Test
	void 탈퇴한_계정은_목록에_없다() throws Exception {
		String prefix = prefix();
		User alive = users.saveAndFlush(User.social(prefix + "alive@example.com", OffsetDateTime.now()));
		User gone = users.saveAndFlush(User.social(prefix + "gone@example.com", OffsetDateTime.now()));
		gone.delete(OffsetDateTime.now());
		users.saveAndFlush(gone);

		assertThat(ids(tokenOf(newAdmin()), "?q=" + prefix)).containsExactly(alive.getId());
	}

	@Test
	void 정지_칸은_지금_정지_중일_때만_채우고_기한이_지나면_비운다() throws Exception {
		String prefix = prefix();
		User forever = users.saveAndFlush(User.social(prefix + "forever@example.com", OffsetDateTime.now()));
		User month = users.saveAndFlush(User.social(prefix + "month@example.com", OffsetDateTime.now()));
		jdbc.update("UPDATE users SET suspended_at = now(), suspended_until = NULL, suspended_reason = '욕설' WHERE id = ?",
				forever.getId());
		jdbc.update("UPDATE users SET suspended_at = now(), suspended_until = now() + interval '30 days', "
				+ "suspended_reason = '도배' WHERE id = ?", month.getId());
		String admin = tokenOf(newAdmin());

		list(admin, "?q=" + prefix + "&sort=EMAIL").andExpect(jsonPath("$.users[0].email").value(prefix + "forever@example.com"))
			.andExpect(jsonPath("$.users[0].suspendedAt").isString())
			.andExpect(jsonPath("$.users[0].suspendedUntil").isEmpty())
			.andExpect(jsonPath("$.users[0].suspendReason").value("욕설"))
			.andExpect(jsonPath("$.users[1].suspendedUntil").isString())
			.andExpect(jsonPath("$.users[1].suspendReason").value("도배"));

		clock.advance(Duration.ofDays(31));
		list(tokenOf(newAdmin()), "?q=" + prefix + "&sort=EMAIL")
			.andExpect(jsonPath("$.users[0].suspendReason").value("욕설"))
			.andExpect(jsonPath("$.users[1].suspendedAt").isEmpty())
			.andExpect(jsonPath("$.users[1].suspendedUntil").isEmpty())
			.andExpect(jsonPath("$.users[1].suspendReason").isEmpty());
	}

	@Test
	void 틀린_요청_값은_400_INVALID_REQUEST이고_field로_칸을_알린다() throws Exception {
		String admin = tokenOf(newAdmin());
		String[][] cases = { { "?sort=newest", "sort" }, { "?sort=LATEST", "sort" }, { "?size=0", "size" },
				{ "?size=51", "size" }, { "?size=abc", "size" }, { "?cursor=abc", "cursor" },
				{ "?sort=EMAIL&cursor=***", "cursor" }, { "?q=" + "a".repeat(255), "q" } };
		for (String[] c : cases) {
			list(admin, c[0]).andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
				.andExpect(jsonPath("$.field").value(c[1]));
		}
	}

	@Test
	void size가_없으면_20개씩_준다() throws Exception {
		String prefix = prefix();
		for (int i = 0; i < 21; i++) {
			users.saveAndFlush(User.social(prefix + i + "@example.com", OffsetDateTime.now()));
		}

		list(tokenOf(newAdmin()), "?q=" + prefix).andExpect(jsonPath("$.users.length()").value(20))
			.andExpect(jsonPath("$.nextCursor").isString());
	}

	private ResultActions list(String access, String query) throws Exception {
		return mvc.perform(get("/auth/admin/users" + query).header("Authorization", "Bearer " + access));
	}

	private List<Long> ids(String access, String query) throws Exception {
		String body = list(access, query).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
		List<Number> ids = JsonPath.read(body, "$.users[*].userId");
		return ids.stream().map(Number::longValue).toList();
	}

	private String tokenOf(User user) {
		return tokens.issue(user.getId()).accessToken();
	}

	// 관리자는 DB에서 role을 직접 바꿔 정한다(spec/admin.md 1장).
	private User newAdmin() {
		User user = users.saveAndFlush(User.social(newEmail("admin"), OffsetDateTime.now()));
		jdbc.update("UPDATE users SET role = 'ADMIN' WHERE id = ?", user.getId());
		return users.findById(user.getId()).orElseThrow();
	}

	private static String prefix() {
		return "p" + UUID.randomUUID().toString().substring(0, 8);
	}

	private static String newEmail(String head) {
		return head + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
	}

}
