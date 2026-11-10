package com.lolog.auth.email;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.lolog.auth.FakeMailer;
import com.lolog.auth.MutableClock;
import com.lolog.auth.TestContainers;
import com.lolog.auth.email.EmailCodeStore.Purpose;
import com.lolog.auth.token.TokenService;
import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

// 비밀번호 찾기·바꾸기(FR-AUTH-07). 메일은 FakeMailer가 받는다. Docker가 켜져 있어야 한다.
@SpringBootTest
@AutoConfigureMockMvc
@Import({ TestContainers.class, MutableClock.Config.class })
class PasswordApiTests {

	static final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

	@Autowired
	MockMvc mvc;

	@Autowired
	FakeMailer mailer;

	@Autowired
	UserRepository users;

	@Autowired
	EmailCodeStore codes;

	@Autowired
	TokenService tokens;

	@Autowired
	MutableClock clock;

	@Autowired
	@Qualifier(PasswordResetMailConfig.EXECUTOR)
	ThreadPoolTaskExecutor mailExecutor;

	@BeforeEach
	void reset() {
		mailer.fail.set(false);
		clock.reset();
	}

	// ── 찾기: 번호 요청 ──

	@Test
	void 비밀번호가_있는_계정이면_204이고_뒤에서_6자리_번호_메일을_보낸다() throws Exception {
		String email = passwordUser("password1").getEmail();

		requestCode(email.toUpperCase()).andExpect(status().isNoContent());

		FakeMailer.Mail mail = awaitMail(email);
		assertThat(mail.kind()).isEqualTo(FakeMailer.Kind.RESET_CODE);
		assertThat(mail.code()).matches("[0-9]{6}");
	}

	@Test
	void 소셜로만_가입한_계정이면_204이고_번호_대신_안내_메일이다() throws Exception {
		String email = newEmail();
		users.saveAndFlush(User.social(email, OffsetDateTime.now()));

		requestCode(email).andExpect(status().isNoContent());

		FakeMailer.Mail mail = awaitMail(email);
		assertThat(mail.kind()).isEqualTo(FakeMailer.Kind.RESET_SOCIAL_ONLY);
		assertThat(mail.code()).isNull();
	}

	@Test
	void 가입_안_된_이메일이면_204이고_아무것도_보내지_않는다() throws Exception {
		String email = newEmail();

		requestCode(email).andExpect(status().isNoContent());

		awaitIdle();
		assertThat(mailer.count(email)).isZero();
	}

	@Test
	void 같은_이메일로_60초_안에_다시_요청하면_429다_가입_안_된_이메일도_같다() throws Exception {
		String registered = passwordUser("password1").getEmail();
		String unknown = newEmail();
		requestCode(registered).andExpect(status().isNoContent());
		requestCode(unknown).andExpect(status().isNoContent());

		requestCode(registered).andExpect(status().isTooManyRequests())
			.andExpect(jsonPath("$.code").value("TOO_MANY_REQUESTS"));
		requestCode(unknown).andExpect(status().isTooManyRequests())
			.andExpect(jsonPath("$.code").value("TOO_MANY_REQUESTS"));
	}

	@Test
	void 메일을_보내지_못해도_204이고_바로_다시_요청할_수_있다() throws Exception {
		String email = passwordUser("password1").getEmail();
		mailer.fail.set(true);

		requestCode(email).andExpect(status().isNoContent());
		awaitIdle();
		assertThat(mailer.count(email)).isZero();

		mailer.fail.set(false);
		requestCode(email).andExpect(status().isNoContent());
		assertThat(awaitMail(email).code()).matches("[0-9]{6}");
	}

	@Test
	void 번호_요청의_이메일_형식이_틀리면_400이다() throws Exception {
		requestCode("not-email").andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
			.andExpect(jsonPath("$.field").value("email"));
	}

	// ── 찾기: 새 비밀번호 정하기 ──

	@Test
	void 맞는_번호면_204이고_새_비밀번호로만_로그인되며_전에_받은_리프레시_토큰은_못_쓴다() throws Exception {
		User user = passwordUser("password1");
		String oldRefresh = tokens.issue(user.getId()).refreshToken();
		requestCode(user.getEmail()).andExpect(status().isNoContent());
		String code = awaitMail(user.getEmail()).code();

		resetPassword(user.getEmail(), code, "newpass22").andExpect(status().isNoContent());

		login(user.getEmail(), "password1").andExpect(status().isUnauthorized());
		login(user.getEmail(), "newpass22").andExpect(status().isOk());
		refresh(oldRefresh).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
	}

	@Test
	void 번호가_틀리면_400_INVALID_CODE이고_5번_틀리면_CODE_EXPIRED다() throws Exception {
		String email = passwordUser("password1").getEmail();
		requestCode(email).andExpect(status().isNoContent());
		String code = awaitMail(email).code();
		String wrong = code.equals("000000") ? "111111" : "000000";

		for (int i = 0; i < 4; i++) {
			resetPassword(email, wrong, "newpass22").andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("INVALID_CODE"));
		}
		resetPassword(email, wrong, "newpass22").andExpect(jsonPath("$.code").value("INVALID_CODE"));
		resetPassword(email, code, "newpass22").andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.code").value("CODE_EXPIRED"));
	}

	@Test
	void 번호는_한_번만_쓰고_10분이_지나면_CODE_EXPIRED다() throws Exception {
		String email = passwordUser("password1").getEmail();
		codes.save(Purpose.PASSWORD_RESET, email, "123456");
		resetPassword(email, "123456", "newpass22").andExpect(status().isNoContent());
		resetPassword(email, "123456", "newpass33").andExpect(jsonPath("$.code").value("CODE_EXPIRED"));

		codes.save(Purpose.PASSWORD_RESET, email, "654321");
		clock.advance(Duration.ofMinutes(10).plusSeconds(1));
		resetPassword(email, "654321", "newpass33").andExpect(jsonPath("$.code").value("CODE_EXPIRED"));
	}

	@Test
	void 가입_인증번호로는_비밀번호를_바꿀_수_없고_반대도_안_된다() throws Exception {
		String email = passwordUser("password1").getEmail();
		codes.save(email, "123456");

		resetPassword(email, "123456", "newpass22").andExpect(jsonPath("$.code").value("CODE_EXPIRED"));

		// 비밀번호 찾기 번호는 가입 번호 자리에 들어가지 않는다(가입 번호 123456은 그대로 남아 있다).
		codes.save(Purpose.PASSWORD_RESET, email, "222222");
		assertThat(codes.check(email, "222222")).isEqualTo(EmailCodeStore.Result.WRONG);
		assertThat(codes.check(email, "123456")).isEqualTo(EmailCodeStore.Result.MATCHED);
	}

	@Test
	void 번호를_받지_않은_소셜_계정이나_없는_계정은_CODE_EXPIRED다() throws Exception {
		String social = newEmail();
		users.saveAndFlush(User.social(social, OffsetDateTime.now()));
		requestCode(social).andExpect(status().isNoContent());
		awaitMail(social);

		resetPassword(social, "123456", "newpass22").andExpect(jsonPath("$.code").value("CODE_EXPIRED"));
		resetPassword(newEmail(), "123456", "newpass22").andExpect(jsonPath("$.code").value("CODE_EXPIRED"));
	}

	@Test
	void 새_비밀번호가_규칙에_안_맞으면_400과_newPassword_칸이다() throws Exception {
		String email = passwordUser("password1").getEmail();
		for (String bad : new String[] { "short1", "onlyletters", "12345678", "가".repeat(24) + "a1" }) {
			codes.save(Purpose.PASSWORD_RESET, email, "123456");
			resetPassword(email, "123456", bad).andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
				.andExpect(jsonPath("$.field").value("newPassword"));
		}
	}

	// ── 바꾸기 ──

	@Test
	void 지금_비밀번호가_맞으면_200과_새_토큰이고_다른_기기의_리프레시_토큰은_못_쓴다() throws Exception {
		User user = passwordUser("password1");
		String otherDevice = tokens.issue(user.getId()).refreshToken();
		String access = tokens.issue(user.getId()).accessToken();

		String body = change(access, "password1", "newpass22").andExpect(status().isOk())
			.andExpect(jsonPath("$.accessToken").isString())
			.andExpect(jsonPath("$.accessTokenExpiresIn").value(1800))
			.andReturn()
			.getResponse()
			.getContentAsString();

		refresh(otherDevice).andExpect(status().isUnauthorized());
		refresh(JsonPath.read(body, "$.refreshToken")).andExpect(status().isOk());
		login(user.getEmail(), "password1").andExpect(status().isUnauthorized());
		login(user.getEmail(), "newpass22").andExpect(status().isOk());
	}

	@Test
	void 지금_비밀번호가_틀리면_401_INVALID_CREDENTIALS이고_바뀌지_않는다() throws Exception {
		User user = passwordUser("password1");
		String access = tokens.issue(user.getId()).accessToken();

		change(access, "wrongpass1", "newpass22").andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
		login(user.getEmail(), "password1").andExpect(status().isOk());
	}

	@Test
	void 비밀번호가_없는_계정은_400_INVALID_REQUEST와_currentPassword_칸이다() throws Exception {
		User user = users.saveAndFlush(User.social(newEmail(), OffsetDateTime.now()));

		change(tokens.issue(user.getId()).accessToken(), "anything1", "newpass22").andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
			.andExpect(jsonPath("$.field").value("currentPassword"));
	}

	@Test
	void 바꾸기는_액세스_토큰이_없으면_401_INVALID_TOKEN이고_새_비밀번호_규칙이_틀리면_400이다() throws Exception {
		mvc.perform(post("/auth/me/password").contentType(MediaType.APPLICATION_JSON)
			.content("{\"currentPassword\":\"a\",\"newPassword\":\"b\"}"))
			.andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("INVALID_TOKEN"));

		User user = passwordUser("password1");
		change(tokens.issue(user.getId()).accessToken(), "password1", "short").andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.field").value("newPassword"));
	}

	private User passwordUser(String password) {
		return users.saveAndFlush(User.withPassword(newEmail(), encoder.encode(password), OffsetDateTime.now()));
	}

	// 뒤에서 보내는 메일이 올 때까지 기다린다(최대 5초).
	private FakeMailer.Mail awaitMail(String email) throws InterruptedException {
		for (int i = 0; i < 100 && mailer.count(email) == 0; i++) {
			Thread.sleep(50);
		}
		return mailer.last(email);
	}

	// 메일 실행기에 남은 일이 없을 때까지 기다린다(최대 5초).
	private void awaitIdle() throws InterruptedException {
		for (int i = 0; i < 100; i++) {
			if (mailExecutor.getActiveCount() == 0 && mailExecutor.getThreadPoolExecutor().getQueue().isEmpty()) {
				Thread.sleep(50);
				if (mailExecutor.getActiveCount() == 0) {
					return;
				}
			}
			Thread.sleep(50);
		}
	}

	private ResultActions requestCode(String email) throws Exception {
		return mvc.perform(post("/auth/password/reset/code").contentType(MediaType.APPLICATION_JSON)
			.content("{\"email\":\"" + email + "\"}"));
	}

	private ResultActions resetPassword(String email, String code, String newPassword) throws Exception {
		return mvc.perform(post("/auth/password/reset").contentType(MediaType.APPLICATION_JSON)
			.content("{\"email\":\"" + email + "\",\"code\":\"" + code + "\",\"newPassword\":\"" + newPassword + "\"}"));
	}

	private ResultActions change(String accessToken, String current, String newPassword) throws Exception {
		return mvc.perform(post("/auth/me/password").header("Authorization", "Bearer " + accessToken)
			.contentType(MediaType.APPLICATION_JSON)
			.content("{\"currentPassword\":\"" + current + "\",\"newPassword\":\"" + newPassword + "\"}"));
	}

	private ResultActions login(String email, String password) throws Exception {
		return mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
			.content("{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}"));
	}

	private ResultActions refresh(String refreshToken) throws Exception {
		return mvc.perform(post("/auth/refresh").contentType(MediaType.APPLICATION_JSON)
			.content("{\"refreshToken\":\"" + refreshToken + "\"}"));
	}

	private static String newEmail() {
		return "p" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
	}

}
