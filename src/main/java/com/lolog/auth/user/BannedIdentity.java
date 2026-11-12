package com.lolog.auth.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;

// 관리자가 탈퇴시킨 계정의 이메일·소셜 계정(LOLog-docs PR #59 spec/admin.md 3장).
// 여기 적힌 이메일·소셜 계정으로는 가입·소셜 로그인·소셜 연결을 할 수 없다(409 ACCOUNT_BANNED).
@Entity
@Table(name = "banned_identities")
public class BannedIdentity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 10)
	private Kind kind;

	// 소문자 이메일 또는 그 회사의 사용자 번호
	@Column(nullable = false, length = 254)
	private String value;

	@Column(name = "user_id", nullable = false)
	private Long userId;

	@Column(name = "created_at", nullable = false)
	private OffsetDateTime createdAt;

	protected BannedIdentity() {
	}

	public BannedIdentity(Kind kind, String value, long userId, OffsetDateTime now) {
		this.kind = kind;
		this.value = value;
		this.userId = userId;
		this.createdAt = now;
	}

	public Kind getKind() {
		return kind;
	}

	public String getValue() {
		return value;
	}

	public Long getUserId() {
		return userId;
	}

	public enum Kind {

		EMAIL, GOOGLE, NAVER;

		public static Kind of(SocialProvider provider) {
			return switch (provider) {
				case GOOGLE -> GOOGLE;
				case NAVER -> NAVER;
			};
		}

	}

}
