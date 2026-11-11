package com.lolog.auth.admin;

import com.lolog.auth.me.UserDataDeleter;
import com.lolog.auth.token.CurrentUser;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

// 관리자 주소 /auth/admin/**(LOLog-docs PR #59 spec/admin.md 7장).
// 액세스 토큰을 먼저 보고(401), 관리자가 아니면 403 FORBIDDEN, 그다음에 요청 값을 검사한다(400).
@RestController
public class AdminController {

	private final AdminUserService adminUsers;

	private final AdminSuspensionService suspensions;

	private final SuspensionNotifier suspensionNotifier;

	private final AdminWithdrawService withdrawals;

	private final UserDataDeleter userDataDeleter;

	public AdminController(AdminUserService adminUsers, AdminSuspensionService suspensions,
			SuspensionNotifier suspensionNotifier, AdminWithdrawService withdrawals, UserDataDeleter userDataDeleter) {
		this.adminUsers = adminUsers;
		this.suspensions = suspensions;
		this.suspensionNotifier = suspensionNotifier;
		this.withdrawals = withdrawals;
		this.userDataDeleter = userDataDeleter;
	}

	// GET /auth/admin/users → 200 { users, nextCursor }
	@GetMapping("/auth/admin/users")
	public AdminUserService.AdminUserPage users(@CurrentUser Long userId,
			@RequestParam(required = false) String q, @RequestParam(required = false) String sort,
			@RequestParam(required = false) String cursor, @RequestParam(required = false) String size) {
		adminUsers.requireAdmin(userId);
		return adminUsers.list(q, sort, cursor, parseSize(size));
	}

	// POST /auth/admin/users/{id}/suspend → 204. lolog-api 알림은 한 번 불러 보고, 실패하면 뒤에서 다시 부른다.
	// 본문 칸은 문자열로 받아 관리자 확인 뒤에 검사한다(JSON 모양이 틀린 것만 먼저 400).
	@PostMapping("/auth/admin/users/{id}/suspend")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void suspend(@CurrentUser Long userId, @PathVariable long id, @RequestBody SuspendRequest request) {
		adminUsers.requireAdmin(userId);
		suspensions.suspend(id, request.duration(), request.reason());
		suspensionNotifier.tryNotify(id);
	}

	// DELETE /auth/admin/users/{id}/suspend → 204
	@DeleteMapping("/auth/admin/users/{id}/suspend")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void unsuspend(@CurrentUser Long userId, @PathVariable long id) {
		adminUsers.requireAdmin(userId);
		suspensions.unsuspend(id);
		suspensionNotifier.tryNotify(id);
	}

	// DELETE /auth/admin/users/{id} → 204. 본인 탈퇴(DELETE /auth/me)처럼 lolog-api 데이터 삭제는 한 번 불러 보고,
	// 실패하면 뒤에서 다시 부른다. 그 계정의 이메일·소셜 계정으로는 다시 가입할 수 없다.
	@DeleteMapping("/auth/admin/users/{id}")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void withdraw(@CurrentUser Long userId, @PathVariable long id) {
		adminUsers.requireAdmin(userId);
		withdrawals.withdraw(id);
		userDataDeleter.tryDelete(id);
	}

	// SuspendRequest(spec/admin.md 7장). duration MONTH_1·MONTH_3·MONTH_6·PERMANENT, reason 1~200자
	public record SuspendRequest(String duration, String reason) {
	}

	// size가 숫자가 아니어도 관리자 확인 뒤에 400을 주려고 직접 바꾼다.
	private static Integer parseSize(String size) {
		if (size == null || size.isEmpty()) {
			return null;
		}
		if (!size.matches("\\d{1,3}")) {
			return -1;
		}
		return Integer.parseInt(size);
	}

}
