package com.lolog.auth.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.lolog.auth.user.Role;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class AccessTokenIssuerTests {

	@Test
	void 비밀값이_32바이트보다_짧으면_만들지_않는다() {
		assertThatThrownBy(() -> new AccessTokenIssuer("a".repeat(31), Clock.systemUTC()))
			.isInstanceOf(IllegalStateException.class);
	}

	@Test
	void 클레임은_sub_typ_iat_exp_role이고_exp는_iat_더하기_1800초다() throws Exception {
		Instant now = Instant.parse("2026-11-08T03:00:00.789Z");
		String token = new AccessTokenIssuer(AccessTokens.SECRET, Clock.fixed(now, ZoneOffset.UTC)).issue(42, Role.USER);

		var claims = AccessTokens.verify(token, AccessTokens.SECRET);
		assertThat(claims.getClaims().keySet()).containsExactlyInAnyOrder("sub", "typ", "iat", "exp", "role");
		assertThat(claims.getSubject()).isEqualTo("42");
		assertThat(claims.getStringClaim("typ")).isEqualTo("access");
		assertThat(claims.getStringClaim("role")).isEqualTo("USER");
		assertThat(claims.getIssueTime().toInstant()).isEqualTo(Instant.parse("2026-11-08T03:00:00Z"));
		assertThat(claims.getExpirationTime().toInstant()).isEqualTo(Instant.parse("2026-11-08T03:30:00Z"));
	}

	@Test
	void 관리자는_role이_ADMIN이다() throws Exception {
		String token = new AccessTokenIssuer(AccessTokens.SECRET, Clock.systemUTC()).issue(7, Role.ADMIN);

		assertThat(AccessTokens.verify(token, AccessTokens.SECRET).getStringClaim("role")).isEqualTo("ADMIN");
	}

	@Test
	void 다른_비밀값으로는_검사가_통과하지_않는다() {
		String token = new AccessTokenIssuer(AccessTokens.SECRET, Clock.systemUTC()).issue(1, Role.USER);

		assertThatThrownBy(() -> AccessTokens.verify(token, "another-secret-at-least-32-bytes-long!!"))
			.isInstanceOf(IllegalStateException.class);
	}

}
