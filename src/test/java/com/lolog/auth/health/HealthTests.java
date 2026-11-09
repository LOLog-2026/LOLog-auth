package com.lolog.auth.health;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.lolog.auth.TestContainers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

// DB·Redis가 모두 있으면 토큰 없이 200 UP이다. Docker가 켜져 있어야 한다.
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestContainers.class)
class HealthTests {

	@Autowired
	MockMvc mvc;

	@Test
	void 토큰_없이_200_UP이다() throws Exception {
		mvc.perform(get("/auth/health"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.length()").value(1))
			.andExpect(jsonPath("$.status").value("UP"));
	}

}
