package com.lolog.auth.email;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.lolog.auth.MutableClock;
import com.lolog.auth.TestContainers;
import com.lolog.auth.token.AccessTokens;
import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
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

// 이메일 가입·로그인(FR-AUTH-01). Docker가 켜져 있어야 한다.
@SpringBootTest
@AutoConfigureMockMvc
@Import({ TestContainers.class, MutableClock.Config.class })
class EmailAuthApiTests {

	@Autowired
	MockMvc mvc;

	@Autowired
	UserRepository users;

	@Autowired
	MutableClock clock;

	@BeforeEach
	void resetClock() {
		clock.reset();
	}

	@Test
	void 가입하면_201과_토큰_한_벌이다() throws Exception {
		String body = signup(newEmail(), "password1").andExpect(status().isCreated())
			.andExpect(jsonPath("$.accessToken").isString())
			.andExpect(jsonPath("$.refreshToken").isString())
			.andExpect(jsonPath("$.accessTokenExpiresIn").value(1800))
			.andReturn()
			.getResponse()
			.getContentAsString();

		JWTClaimsSet claims = AccessTokens.verify(JsonPath.read(body, "$.accessToken"), AccessTokens.SECRET);
		assertThat(claims.getSubject()).matches("\\d+");
		assertThat(claims.getStringClaim("typ")).isEqualTo("access");
		assertThat(claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()).isEqualTo(1_800_000);
		assertThat(SignedJWT.parse(JsonPath.read(body, "$.accessToken")).getHeader().getAlgorithm())
			.isEqualTo(JWSAlgorithm.HS256);
	}

	@Test
	void 이메일은_소문자로_저장하고_비밀번호는_BCrypt_해시로_저장한다() throws Exception {
		String email = newEmail();
		signup(email.toUpperCase(), "password1").andExpect(status().isCreated());

		User user = users.findByEmailAndDeletedAtIsNull(email).orElseThrow();
		assertThat(user.getPasswordHash()).startsWith("$2").doesNotContain("password1");
	}

	@Test
	void 이미_가입된_이메일이면_대소문자가_달라도_409_ACCOUNT_EXISTS다() throws Exception {
		String email = newEmail();
		signup(email, "password1").andExpect(status().isCreated());

		signup(email.toUpperCase(), "password2").andExpect(status().isConflict())
			.andExpect(jsonPath("$.code").value("ACCOUNT_EXISTS"));
	}

	@Test
	void 소셜로_가입한_이메일이어도_409_ACCOUNT_EXISTS다() throws Exception {
		String email = newEmail();
		users.saveAndFlush(User.social(email, OffsetDateTime.now()));

		signup(email, "password1").andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("ACCOUNT_EXISTS"));
	}

	@Test
	void 탈퇴한_계정의_이메일로는_다시_가입할_수_있다() throws Exception {
		String email = newEmail();
		signup(email, "password1").andExpect(status().isCreated());
		User old = users.findByEmailAndDeletedAtIsNull(email).orElseThrow();
		old.delete(OffsetDateTime.now());
		users.saveAndFlush(old);

		signup(email, "password2").andExpect(status().isCreated());
	}

	@Test
	void 가입_입력이_틀리면_400_INVALID_REQUEST와_틀린_칸이다() throws Exception {
		signup("not-an-email", "password1").andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
			.andExpect(jsonPath("$.field").value("email"));
		signup("a".repeat(243) + "@example.com", "password1").andExpect(jsonPath("$.field").value("email"));
		signup(newEmail(), "short1").andExpect(jsonPath("$.field").value("password"));
		signup(newEmail(), "a1".repeat(32) + "x").andExpect(jsonPath("$.field").value("password"));
		signup(newEmail(), "onlyletters").andExpect(jsonPath("$.field").value("password"));
		signup(newEmail(), "12345678").andExpect(jsonPath("$.field").value("password"));
		// 64자 안이지만 72바이트를 넘는 비밀번호(BCrypt 한도)
		signup(newEmail(), "a1" + "가".repeat(30)).andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.field").value("password"));
		post("/auth/signup", "{\"email\":\"" + newEmail() + "\"}").andExpect(jsonPath("$.field").value("password"));
	}

	@Test
	void 경계값_비밀번호_8자와_64자는_가입된다() throws Exception {
		signup(newEmail(), "abcdefg1").andExpect(status().isCreated());
		signup(newEmail(), "a1".repeat(32)).andExpect(status().isCreated());
	}

	@Test
	void 가입한_이메일과_비밀번호로_로그인하면_200과_토큰이다() throws Exception {
		String email = newEmail();
		signup(email, "password1").andExpect(status().isCreated());

		login(email.toUpperCase(), "password1").andExpect(status().isOk())
			.andExpect(jsonPath("$.accessToken").isString())
			.andExpect(jsonPath("$.refreshToken").isString())
			.andExpect(jsonPath("$.accessTokenExpiresIn").value(1800));
	}

	@Test
	void 비밀번호나_이메일이_틀리면_같은_401_INVALID_CREDENTIALS다() throws Exception {
		String email = newEmail();
		signup(email, "password1").andExpect(status().isCreated());

		login(email, "password2").andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
		login(newEmail(), "password1").andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
	}

	@Test
	void 로그인은_비밀번호_규칙을_검사하지_않는다() throws Exception {
		login(newEmail(), "x").andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
		login(newEmail(), "가".repeat(100)).andExpect(status().isUnauthorized());
	}

	@Test
	void 소셜로만_가입한_계정은_비밀번호로_로그인되지_않는다() throws Exception {
		String email = newEmail();
		users.saveAndFlush(User.social(email, OffsetDateTime.now()));

		login(email, "password1").andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
	}

	@Test
	void 탈퇴한_계정으로는_로그인되지_않는다() throws Exception {
		String email = newEmail();
		signup(email, "password1").andExpect(status().isCreated());
		User user = users.findByEmailAndDeletedAtIsNull(email).orElseThrow();
		user.delete(OffsetDateTime.now());
		users.saveAndFlush(user);

		login(email, "password1").andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
	}

	@Test
	void 로그인_값이_빠지면_400_INVALID_REQUEST다() throws Exception {
		post("/auth/login", "{\"email\":\"a@example.com\"}").andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.field").value("password"));
	}

	private ResultActions signup(String email, String password) throws Exception {
		return post("/auth/signup", json(email, password));
	}

	private ResultActions login(String email, String password) throws Exception {
		return post("/auth/login", json(email, password));
	}

	private ResultActions post(String url, String body) throws Exception {
		return mvc.perform(
				org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post(url)
					.contentType(MediaType.APPLICATION_JSON)
					.content(body));
	}

	private static String json(String email, String password) {
		return "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}";
	}

	private static String newEmail() {
		return "u" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
	}

}
