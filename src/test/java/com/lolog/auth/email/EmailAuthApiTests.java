package com.lolog.auth.email;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.lolog.auth.FakeMailer;
import com.lolog.auth.MutableClock;
import com.lolog.auth.TestContainers;
import com.lolog.auth.token.AccessTokens;
import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Duration;
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

// 이메일 가입·로그인과 가입 인증번호(FR-AUTH-01). Docker가 켜져 있어야 한다.
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

	@Autowired
	FakeMailer mailer;

	@BeforeEach
	void reset() {
		clock.reset();
		mailer.fail.set(false);
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
	void 이미_가입된_이메일로_번호를_요청하면_204이고_번호_대신_안내_메일을_보낸다() throws Exception {
		String email = newEmail();
		signup(email, "password1").andExpect(status().isCreated());
		clock.advance(EmailCodeStore.COOLDOWN);

		requestCode(email.toUpperCase()).andExpect(status().isNoContent());
		assertThat(mailer.last(email).code()).isNull();
		// 번호를 받지 못하니 가입은 409가 아니라 CODE_EXPIRED로 끝난다(가입 여부가 드러나지 않음).
		signupWithCode(email, "password2", "000000").andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.code").value("CODE_EXPIRED"));
	}

	@Test
	void 소셜로_가입한_이메일도_안내_메일이다() throws Exception {
		String email = newEmail();
		users.saveAndFlush(User.social(email, OffsetDateTime.now()));

		requestCode(email).andExpect(status().isNoContent());
		assertThat(mailer.last(email).code()).isNull();
	}

	@Test
	void 번호를_받은_뒤_다른_방법으로_가입됐으면_번호가_맞을_때만_409_ACCOUNT_EXISTS다() throws Exception {
		String email = newEmail();
		requestCode(email).andExpect(status().isNoContent());
		String code = mailer.last(email).code();
		users.saveAndFlush(User.social(email, OffsetDateTime.now()));

		signupWithCode(email, "password1", wrong(code)).andExpect(jsonPath("$.code").value("INVALID_CODE"));
		signupWithCode(email.toUpperCase(), "password1", code).andExpect(status().isConflict())
			.andExpect(jsonPath("$.code").value("ACCOUNT_EXISTS"));
	}

	@Test
	void 탈퇴한_계정의_이메일로는_다시_가입할_수_있다() throws Exception {
		String email = newEmail();
		signup(email, "password1").andExpect(status().isCreated());
		User old = users.findByEmailAndDeletedAtIsNull(email).orElseThrow();
		old.delete(OffsetDateTime.now());
		users.saveAndFlush(old);
		clock.advance(EmailCodeStore.COOLDOWN);

		signup(email, "password2").andExpect(status().isCreated());
		assertThat(mailer.last(email).code()).isNotNull();
	}

	@Test
	void 가입_입력이_틀리면_400_INVALID_REQUEST와_틀린_칸이다() throws Exception {
		signupWithCode("not-an-email", "password1", "123456").andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
			.andExpect(jsonPath("$.field").value("email"));
		signupWithCode("a".repeat(243) + "@example.com", "password1", "123456").andExpect(jsonPath("$.field").value("email"));
		signupWithCode(newEmail(), "short1", "123456").andExpect(jsonPath("$.field").value("password"));
		signupWithCode(newEmail(), "a1".repeat(32) + "x", "123456").andExpect(jsonPath("$.field").value("password"));
		signupWithCode(newEmail(), "onlyletters", "123456").andExpect(jsonPath("$.field").value("password"));
		signupWithCode(newEmail(), "12345678", "123456").andExpect(jsonPath("$.field").value("password"));
		// 64자 안이지만 72바이트를 넘는 비밀번호(BCrypt 한도)
		signupWithCode(newEmail(), "a1" + "가".repeat(30), "123456").andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.field").value("password"));
		post("/auth/signup", "{\"email\":\"" + newEmail() + "\",\"code\":\"123456\"}").andExpect(jsonPath("$.field").value("password"));
		post("/auth/signup", json(newEmail(), "password1")).andExpect(jsonPath("$.field").value("code"));
		signupWithCode(newEmail(), "password1", "12345").andExpect(jsonPath("$.field").value("code"));
		signupWithCode(newEmail(), "password1", "12345a").andExpect(jsonPath("$.field").value("code"));
	}

	@Test
	void 번호를_요청하면_204이고_6자리_번호_메일을_보낸다() throws Exception {
		String email = newEmail();
		requestCode(email.toUpperCase()).andExpect(status().isNoContent());

		assertThat(mailer.last(email).code()).matches("[0-9]{6}");
	}

	@Test
	void 번호_요청의_이메일_형식이_틀리면_400_INVALID_REQUEST다() throws Exception {
		requestCode("not-an-email").andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
			.andExpect(jsonPath("$.field").value("email"));
		post("/auth/email/code", "{}").andExpect(jsonPath("$.field").value("email"));
	}

	@Test
	void 번호가_틀리면_400_INVALID_CODE이고_5번_틀리면_맞는_번호도_CODE_EXPIRED다() throws Exception {
		String email = newEmail();
		requestCode(email).andExpect(status().isNoContent());
		String code = mailer.last(email).code();

		for (int i = 0; i < EmailCodeStore.MAX_TRIES; i++) {
			signupWithCode(email, "password1", wrong(code)).andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("INVALID_CODE"));
		}
		signupWithCode(email, "password1", code).andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.code").value("CODE_EXPIRED"));
	}

	@Test
	void 네_번_틀린_뒤에도_맞는_번호면_가입된다() throws Exception {
		String email = newEmail();
		requestCode(email).andExpect(status().isNoContent());
		String code = mailer.last(email).code();

		for (int i = 0; i < EmailCodeStore.MAX_TRIES - 1; i++) {
			signupWithCode(email, "password1", wrong(code)).andExpect(jsonPath("$.code").value("INVALID_CODE"));
		}
		signupWithCode(email, "password1", code).andExpect(status().isCreated());
	}

	@Test
	void 번호는_10분이_지나면_CODE_EXPIRED다() throws Exception {
		String email = newEmail();
		requestCode(email).andExpect(status().isNoContent());
		String code = mailer.last(email).code();

		clock.advance(EmailCodeStore.VALIDITY);
		signupWithCode(email, "password1", code).andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.code").value("CODE_EXPIRED"));
	}

	@Test
	void 번호는_10분_안이면_쓸_수_있다() throws Exception {
		String email = newEmail();
		requestCode(email).andExpect(status().isNoContent());

		clock.advance(EmailCodeStore.VALIDITY.minusSeconds(1));
		signupWithCode(email, "password1", mailer.last(email).code()).andExpect(status().isCreated());
	}

	@Test
	void 번호를_받지_않고_가입하면_CODE_EXPIRED다() throws Exception {
		signupWithCode(newEmail(), "password1", "123456").andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.code").value("CODE_EXPIRED"));
	}

	@Test
	void 맞게_쓴_번호는_다시_쓸_수_없다() throws Exception {
		String email = newEmail();
		requestCode(email).andExpect(status().isNoContent());
		String code = mailer.last(email).code();
		signupWithCode(email, "password1", code).andExpect(status().isCreated());

		signupWithCode(email, "password1", code).andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.code").value("CODE_EXPIRED"));
	}

	@Test
	void 같은_이메일로_60초_안에_다시_요청하면_429이고_지나면_새_번호이며_전_번호는_못_쓴다() throws Exception {
		String email = newEmail();
		requestCode(email).andExpect(status().isNoContent());
		String first = mailer.last(email).code();

		clock.advance(EmailCodeStore.COOLDOWN.minusSeconds(1));
		requestCode(email.toUpperCase()).andExpect(status().isTooManyRequests())
			.andExpect(jsonPath("$.code").value("TOO_MANY_REQUESTS"));
		assertThat(mailer.count(email)).isEqualTo(1);

		clock.advance(Duration.ofSeconds(1));
		requestCode(email).andExpect(status().isNoContent());
		String second = mailer.last(email).code();
		assertThat(mailer.count(email)).isEqualTo(2);

		if (!first.equals(second)) {
			signupWithCode(email, "password1", first).andExpect(jsonPath("$.code").value("INVALID_CODE"));
		}
		signupWithCode(email, "password1", second).andExpect(status().isCreated());
	}

	@Test
	void 가입된_이메일도_60초_간격을_지킨다() throws Exception {
		String email = newEmail();
		users.saveAndFlush(User.social(email, OffsetDateTime.now()));

		requestCode(email).andExpect(status().isNoContent());
		requestCode(email).andExpect(status().isTooManyRequests());
		assertThat(mailer.count(email)).isEqualTo(1);
	}

	@Test
	void 메일을_보내지_못하면_500이고_바로_다시_요청할_수_있다() throws Exception {
		String email = newEmail();
		mailer.fail.set(true);
		requestCode(email).andExpect(status().isInternalServerError())
			.andExpect(jsonPath("$.code").value("INTERNAL_ERROR"));
		signupWithCode(email, "password1", "123456").andExpect(jsonPath("$.code").value("CODE_EXPIRED"));

		mailer.fail.set(false);
		requestCode(email).andExpect(status().isNoContent());
		signupWithCode(email, "password1", mailer.last(email).code()).andExpect(status().isCreated());
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

	// 번호를 요청하고 메일로 받은 번호로 가입한다. 같은 이메일로 다시 부를 때는 60초를 돌린 뒤 부른다.
	private ResultActions signup(String email, String password) throws Exception {
		requestCode(email).andExpect(status().isNoContent());
		return signupWithCode(email, password, mailer.last(User.normalizeEmail(email)).code());
	}

	private ResultActions signupWithCode(String email, String password, String code) throws Exception {
		return post("/auth/signup",
				"{\"email\":\"" + email + "\",\"password\":\"" + password + "\",\"code\":\"" + code + "\"}");
	}

	private ResultActions requestCode(String email) throws Exception {
		return post("/auth/email/code", "{\"email\":\"" + email + "\"}");
	}

	// 맞는 번호와 다른 6자리 번호
	private static String wrong(String code) {
		return "%06d".formatted((Integer.parseInt(code) + 1) % 1_000_000);
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
