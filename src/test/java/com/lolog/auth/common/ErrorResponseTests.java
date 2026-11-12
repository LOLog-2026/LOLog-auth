package com.lolog.auth.common;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.lolog.auth.token.AccessTokenVerifier;
import com.lolog.auth.token.SuspendedUsers;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// 오류가 모두 ErrorResponse { code, message, field } 모양으로 나가는지 시험용 컨트롤러로 확인한다.
@WebMvcTest(ErrorResponseTests.TestController.class)
// @WebMvcTest도 @CurrentUser 처리기(CurrentUserResolver)를 올리므로 그 검사기와 시계를 같이 넣는다.
// 정지 키 확인(SuspendedUsers)은 Redis가 필요해 가짜로 둔다.
@Import({ ErrorResponseTests.TestController.class, GlobalExceptionHandler.class, AccessTokenVerifier.class,
		TimeConfig.class })
class ErrorResponseTests {

	@Autowired
	MockMvc mvc;

	@MockitoBean
	SuspendedUsers suspendedUsers;

	@Test
	void 명세의_오류_코드는_그대로_나간다() throws Exception {
		mvc.perform(get("/test/conflict"))
			.andExpect(status().isConflict())
			.andExpect(jsonPath("$.code").value("ACCOUNT_EXISTS"))
			.andExpect(jsonPath("$.message").isString())
			.andExpect(jsonPath("$.field").isEmpty());
	}

	@Test
	void 검사에_걸리면_400_INVALID_REQUEST와_틀린_칸이다() throws Exception {
		mvc.perform(post("/test/body").contentType(MediaType.APPLICATION_JSON).content("{\"email\":\"\"}"))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
			.andExpect(jsonPath("$.field").value("email"));
	}

	@Test
	void JSON이_아니면_400_INVALID_REQUEST다() throws Exception {
		mvc.perform(post("/test/body").contentType(MediaType.APPLICATION_JSON).content("{"))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
	}

	@Test
	void 모르는_필드는_무시한다() throws Exception {
		mvc.perform(post("/test/body").contentType(MediaType.APPLICATION_JSON)
			.content("{\"email\":\"a@example.com\",\"unknown\":1}")).andExpect(status().isOk());
	}

	@Test
	void 처리하지_못한_예외는_500_INTERNAL_ERROR이고_메시지를_감춘다() throws Exception {
		mvc.perform(get("/test/boom"))
			.andExpect(status().isInternalServerError())
			.andExpect(jsonPath("$.code").value("INTERNAL_ERROR"))
			.andExpect(jsonPath("$.message").value("서버 오류가 발생했습니다."));
	}

	@Test
	void 없는_주소는_404_NOT_FOUND다() throws Exception {
		mvc.perform(get("/test/nothing"))
			.andExpect(status().isNotFound())
			.andExpect(jsonPath("$.code").value("NOT_FOUND"))
			.andExpect(jsonPath("$.field").isEmpty());
	}

	@Test
	void 틀린_메서드는_405_METHOD_NOT_ALLOWED이고_Allow_헤더를_준다() throws Exception {
		mvc.perform(get("/test/body"))
			.andExpect(status().isMethodNotAllowed())
			.andExpect(header().string("Allow", "POST"))
			.andExpect(jsonPath("$.code").value("METHOD_NOT_ALLOWED"));
	}

	@Test
	void JSON이_아닌_Content_Type은_415_UNSUPPORTED_MEDIA_TYPE이다() throws Exception {
		mvc.perform(post("/test/body").contentType(MediaType.TEXT_PLAIN).content("a"))
			.andExpect(status().isUnsupportedMediaType())
			.andExpect(jsonPath("$.code").value("UNSUPPORTED_MEDIA_TYPE"));
		mvc.perform(post("/test/body").content("{\"email\":\"a@example.com\"}"))
			.andExpect(status().isUnsupportedMediaType())
			.andExpect(jsonPath("$.code").value("UNSUPPORTED_MEDIA_TYPE"));
	}

	@Test
	void JSON을_받을_수_없다고_하면_406이다() throws Exception {
		// 본문은 JSON으로 쓸 수 없으니 상태만 본다.
		mvc.perform(get("/test/conflict-ok").accept(MediaType.TEXT_HTML)).andExpect(status().isNotAcceptable());
	}

	@Test
	void 빠진_필수_쿼리는_400_INVALID_REQUEST이고_field는_쿼리_이름이다() throws Exception {
		mvc.perform(get("/test/query"))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
			.andExpect(jsonPath("$.field").value("q"));
	}

	record Body(@NotBlank String email) {
	}

	@RestController
	static class TestController {

		@GetMapping("/test/conflict")
		void conflict() {
			throw new ApiException(HttpStatus.CONFLICT, "ACCOUNT_EXISTS", "이미 가입된 이메일입니다.");
		}

		@PostMapping("/test/body")
		void body(@Valid @RequestBody Body body) {
		}

		@GetMapping("/test/conflict-ok")
		Body ok() {
			return new Body("a@example.com");
		}

		@GetMapping("/test/query")
		void query(@RequestParam String q) {
		}

		@GetMapping("/test/boom")
		void boom() {
			throw new IllegalStateException("password=secret");
		}

	}

}
