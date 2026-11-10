package com.lolog.auth.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import java.util.Locale;

// 회원. 탈퇴하면 행을 지우지 않고 deletedAt만 채운다(FR-AUTH-05).
@Entity
@Table(name = "users")
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false, length = 254)
	private String email;

	// 소셜로만 가입한 회원은 비밀번호가 없다.
	@Column(name = "password_hash", length = 100)
	private String passwordHash;

	@Column(name = "created_at", nullable = false)
	private OffsetDateTime createdAt;

	@Column(name = "deleted_at")
	private OffsetDateTime deletedAt;

	// lolog-api가 이 회원의 데이터를 다 지운 시각. 탈퇴했는데 비어 있으면 다시 부른다.
	@Column(name = "data_deleted_at")
	private OffsetDateTime dataDeletedAt;

	protected User() {
	}

	private User(String email, String passwordHash, OffsetDateTime createdAt) {
		this.email = normalizeEmail(email);
		this.passwordHash = passwordHash;
		this.createdAt = createdAt;
	}

	public static User withPassword(String email, String passwordHash, OffsetDateTime now) {
		return new User(email, passwordHash, now);
	}

	public static User social(String email, OffsetDateTime now) {
		return new User(email, null, now);
	}

	// 이메일은 소문자로 저장하고 찾는다(api-dto.md SignupRequest).
	public static String normalizeEmail(String email) {
		return email.trim().toLowerCase(Locale.ROOT);
	}

	// 비밀번호 찾기·바꾸기(FR-AUTH-07). BCrypt 해시를 받는다.
	public void changePassword(String passwordHash) {
		this.passwordHash = passwordHash;
	}

	public void delete(OffsetDateTime now) {
		this.deletedAt = now;
	}

	public void markDataDeleted(OffsetDateTime now) {
		this.dataDeletedAt = now;
	}

	public boolean isDeleted() {
		return deletedAt != null;
	}

	public Long getId() {
		return id;
	}

	public String getEmail() {
		return email;
	}

	public String getPasswordHash() {
		return passwordHash;
	}

	public OffsetDateTime getCreatedAt() {
		return createdAt;
	}

	public OffsetDateTime getDeletedAt() {
		return deletedAt;
	}

	public OffsetDateTime getDataDeletedAt() {
		return dataDeletedAt;
	}

}
