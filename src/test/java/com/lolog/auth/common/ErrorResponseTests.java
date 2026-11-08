package com.lolog.auth.common;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

// 오류가 모두 ErrorResponse { code, message, field } 모양으로 나가는지 시험용 컨트롤러로 확인한다.
@WebMvcTest(ErrorResponseTests.TestController.class)
@Import({ ErrorResponseTests.TestController.class, GlobalExceptionHandler.class })
class ErrorResponseTests {

	@Autowired
	MockMvc mvc;

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

		@GetMapping("/test/boom")
		void boom() {
			throw new IllegalStateException("password=secret");
		}

	}

}
