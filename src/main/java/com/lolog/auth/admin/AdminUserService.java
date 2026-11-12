package com.lolog.auth.admin;

import com.lolog.auth.common.ApiException;
import com.lolog.auth.user.User;
import com.lolog.auth.user.UserRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

// 관리자 확인과 계정 목록(LOLog-docs PR #59 spec/admin.md 1장·6장, FR-ADMIN-01·04).
@Service
public class AdminUserService {

	static final int DEFAULT_SIZE = 20;

	static final int MAX_SIZE = 50;

	private static final int EMAIL_MAX = 254;

	private final UserRepository users;

	private final EntityManager em;

	private final Clock clock;

	public AdminUserService(UserRepository users, EntityManager em, Clock clock) {
		this.users = users;
		this.em = em;
		this.clock = clock;
	}

	// 관리자인지 DB에서 본다. 토큰의 role 클레임이 아니라 DB를 보므로, 관리자에서 빼면 /auth/admin/**은 바로 막힌다.
	// 탈퇴했거나 없는 회원이면 다른 /auth 주소와 같게 401 INVALID_TOKEN, 관리자가 아니면 403 FORBIDDEN이다.
	@Transactional(readOnly = true)
	public User requireAdmin(long userId) {
		User user = users.findByIdAndDeletedAtIsNull(userId)
			.orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_TOKEN", "회원이 없습니다."));
		if (!user.isAdmin()) {
			throw new ApiException(HttpStatus.FORBIDDEN, "FORBIDDEN", "관리자만 쓸 수 있습니다.");
		}
		return user;
	}

	// 살아 있는 계정 목록. 탈퇴한 계정은 넣지 않는다. q는 이메일 일부(대소문자 무시).
	// cursor는 앱이 해석하지 않는 값이다: NEWEST·OLDEST는 마지막 회원 ID, EMAIL은 마지막 이메일을 base64url로 바꾼 값.
	@Transactional(readOnly = true)
	public AdminUserPage list(String q, String sort, String cursor, Integer size) {
		Sort order = Sort.parse(sort);
		int limit = size == null ? DEFAULT_SIZE : size;
		if (limit < 1 || limit > MAX_SIZE) {
			throw ApiException.invalid("size", "size는 1~50이어야 합니다.");
		}
		String keyword = q == null || q.isBlank() ? null : q.trim().toLowerCase(Locale.ROOT);
		if (keyword != null && keyword.length() > EMAIL_MAX) {
			throw ApiException.invalid("q", "q가 너무 깁니다.");
		}

		StringBuilder jpql = new StringBuilder("select u from User u where u.deletedAt is null");
		if (keyword != null) {
			jpql.append(" and u.email like :pattern escape '\\'");
		}
		Object after = cursor == null || cursor.isEmpty() ? null : order.parseCursor(cursor);
		if (after != null) {
			jpql.append(order.afterCondition);
		}
		jpql.append(order.orderBy);

		TypedQuery<User> query = em.createQuery(jpql.toString(), User.class);
		if (keyword != null) {
			query.setParameter("pattern", "%" + escapeLike(keyword) + "%");
		}
		if (after != null) {
			query.setParameter("after", after);
		}
		List<User> found = query.setMaxResults(limit + 1).getResultList();

		boolean hasNext = found.size() > limit;
		List<User> page = hasNext ? found.subList(0, limit) : found;
		Instant now = clock.instant();
		List<AdminUserItem> items = page.stream().map(user -> AdminUserItem.of(user, now)).toList();
		String nextCursor = hasNext ? order.cursorOf(page.get(page.size() - 1)) : null;
		return new AdminUserPage(items, nextCursor);
	}

	// LIKE의 특수 문자(%, _, \)를 글자 그대로 찾게 한다.
	private static String escapeLike(String value) {
		return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
	}

	// 정렬 종류(초안). 가입일 순서는 회원 ID 순서와 같아(BIGSERIAL) ID로 정렬한다.
	enum Sort {

		NEWEST(" and u.id < :after", " order by u.id desc"),

		OLDEST(" and u.id > :after", " order by u.id asc"),

		// 살아 있는 계정의 이메일은 겹치지 않으므로(uk_users_email_active) 이메일만으로 다음 페이지를 찾는다.
		EMAIL(" and u.email > :after", " order by u.email asc");

		final String afterCondition;

		final String orderBy;

		Sort(String afterCondition, String orderBy) {
			this.afterCondition = afterCondition;
			this.orderBy = orderBy;
		}

		static Sort parse(String value) {
			if (value == null || value.isEmpty()) {
				return NEWEST;
			}
			for (Sort sort : values()) {
				if (sort.name().equals(value)) {
					return sort;
				}
			}
			throw ApiException.invalid("sort", "sort는 NEWEST, OLDEST, EMAIL 중 하나여야 합니다.");
		}

		Object parseCursor(String cursor) {
			try {
				if (this == EMAIL) {
					return new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8);
				}
				if (!cursor.matches("\\d{1,18}")) {
					throw ApiException.invalid("cursor", "cursor가 올바르지 않습니다.");
				}
				return Long.parseLong(cursor);
			}
			catch (IllegalArgumentException e) {
				throw ApiException.invalid("cursor", "cursor가 올바르지 않습니다.");
			}
		}

		String cursorOf(User last) {
			if (this == EMAIL) {
				return Base64.getUrlEncoder().withoutPadding().encodeToString(last.getEmail().getBytes(StandardCharsets.UTF_8));
			}
			return Long.toString(last.getId());
		}

	}

	// 계정 목록 응답(spec/admin.md 7장). nextCursor는 마지막 페이지면 null이다.
	public record AdminUserPage(List<AdminUserItem> users, String nextCursor) {
	}

	// AdminUserItem(spec/admin.md 7장). 정지 칸은 지금 정지 중일 때만 채운다(기한이 지났으면 모두 null).
	// suspendedUntil은 영구 정지면 null이다.
	public record AdminUserItem(long userId, String email, OffsetDateTime createdAt, String role,
			OffsetDateTime suspendedAt, OffsetDateTime suspendedUntil, String suspendReason) {

		static AdminUserItem of(User user, Instant now) {
			boolean suspended = user.isSuspended(now);
			return new AdminUserItem(user.getId(), user.getEmail(), user.getCreatedAt(), user.getRole().name(),
					suspended ? user.getSuspendedAt() : null, suspended ? user.getSuspendedUntil() : null,
					suspended ? user.getSuspendedReason() : null);
		}

	}

}
