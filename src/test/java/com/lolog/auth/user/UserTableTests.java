package com.lolog.auth.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.lolog.auth.TestContainers;
import java.time.OffsetDateTime;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;

// 회원·소셜 연결 테이블의 유니크 제약이 살아 있는 행에만 걸리는지 확인한다.
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(TestContainers.class)
class UserTableTests {

	private static final OffsetDateTime NOW = OffsetDateTime.parse("2026-11-08T12:00:00+09:00");

	@Autowired
	UserRepository users;

	@Autowired
	SocialAccountRepository socialAccounts;

	@Test
	void 이메일은_소문자로_저장한다() {
		User user = users.saveAndFlush(User.withPassword(" A@Example.COM ", "hash", NOW));

		assertThat(user.getEmail()).isEqualTo("a@example.com");
		assertThat(users.findByEmailAndDeletedAtIsNull("a@example.com")).isPresent();
	}

	@Test
	void 살아_있는_계정의_이메일로는_또_만들_수_없다() {
		users.saveAndFlush(User.withPassword("a@example.com", "hash", NOW));

		assertThatThrownBy(() -> users.saveAndFlush(User.social("a@example.com", NOW)))
			.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	void 탈퇴한_계정의_이메일로는_다시_가입할_수_있다() {
		User old = users.saveAndFlush(User.withPassword("a@example.com", "hash", NOW));
		old.delete(NOW);
		users.saveAndFlush(old);

		User again = users.saveAndFlush(User.withPassword("a@example.com", "hash2", NOW));

		assertThat(again.getId()).isNotEqualTo(old.getId());
		assertThat(users.findByEmailAndDeletedAtIsNull("a@example.com")).get()
			.extracting(User::getId)
			.isEqualTo(again.getId());
	}

	@Test
	void 소셜_계정_하나는_살아_있는_회원_하나에만_붙는다() {
		User a = users.saveAndFlush(User.social("a@example.com", NOW));
		User b = users.saveAndFlush(User.social("b@example.com", NOW));
		socialAccounts.saveAndFlush(new SocialAccount(a.getId(), SocialProvider.KAKAO, "k-1", NOW));

		assertThatThrownBy(
				() -> socialAccounts.saveAndFlush(new SocialAccount(b.getId(), SocialProvider.KAKAO, "k-1", NOW)))
			.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	void 회원_하나에는_회사마다_소셜_계정_하나만_붙는다() {
		User a = users.saveAndFlush(User.social("a@example.com", NOW));
		socialAccounts.saveAndFlush(new SocialAccount(a.getId(), SocialProvider.KAKAO, "k-1", NOW));

		assertThatThrownBy(
				() -> socialAccounts.saveAndFlush(new SocialAccount(a.getId(), SocialProvider.KAKAO, "k-2", NOW)))
			.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	void 탈퇴한_회원의_소셜_계정은_다른_회원에_다시_붙일_수_있다() {
		User a = users.saveAndFlush(User.social("a@example.com", NOW));
		SocialAccount link = socialAccounts.saveAndFlush(new SocialAccount(a.getId(), SocialProvider.KAKAO, "k-1", NOW));
		link.delete(NOW);
		socialAccounts.saveAndFlush(link);
		User b = users.saveAndFlush(User.social("b@example.com", NOW));

		socialAccounts.saveAndFlush(new SocialAccount(b.getId(), SocialProvider.KAKAO, "k-1", NOW));

		assertThat(socialAccounts.findByProviderAndProviderUserIdAndDeletedAtIsNull(SocialProvider.KAKAO, "k-1"))
			.get()
			.extracting(SocialAccount::getUserId)
			.isEqualTo(b.getId());
	}

	@Test
	void 주소의_provider는_소문자만_받는다() {
		assertThat(SocialProvider.fromPath("kakao")).contains(SocialProvider.KAKAO);
		assertThat(SocialProvider.fromPath("KAKAO")).isEmpty();
		assertThat(SocialProvider.fromPath("apple")).isEmpty();
	}

}
