package com.lolog.auth.me;

import com.lolog.auth.token.CurrentUser;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MeController {

	private final MeService me;

	private final UserDataDeleter userDataDeleter;

	public MeController(MeService me, UserDataDeleter userDataDeleter) {
		this.me = me;
		this.userDataDeleter = userDataDeleter;
	}

	// GET /auth/me → 200 MeResponse
	@GetMapping("/auth/me")
	public MeService.MeResponse me(@CurrentUser Long userId) {
		return me.me(userId);
	}

	// DELETE /auth/me → 204. 회원 정보는 바로 소프트 삭제하고, lolog-api 데이터 삭제는 한 번 불러 본 뒤
	// 실패하면 뒤에서 다시 부른다. 응답은 lolog-api 결과와 관계없이 204다.
	@DeleteMapping("/auth/me")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void withdraw(@CurrentUser Long userId) {
		me.withdraw(userId);
		userDataDeleter.tryDelete(userId);
	}

}
