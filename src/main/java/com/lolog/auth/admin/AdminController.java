package com.lolog.auth.admin;

import com.lolog.auth.token.CurrentUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// 관리자 주소 /auth/admin/**(LOLog-docs PR #59 spec/admin.md 7장).
// 액세스 토큰을 먼저 보고(401), 관리자가 아니면 403 FORBIDDEN, 그다음에 요청 값을 검사한다(400).
@RestController
public class AdminController {

	private final AdminUserService adminUsers;

	public AdminController(AdminUserService adminUsers) {
		this.adminUsers = adminUsers;
	}

	// GET /auth/admin/users → 200 { users, nextCursor }
	@GetMapping("/auth/admin/users")
	public AdminUserService.AdminUserPage users(@CurrentUser Long userId,
			@RequestParam(required = false) String q, @RequestParam(required = false) String sort,
			@RequestParam(required = false) String cursor, @RequestParam(required = false) String size) {
		adminUsers.requireAdmin(userId);
		return adminUsers.list(q, sort, cursor, parseSize(size));
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
