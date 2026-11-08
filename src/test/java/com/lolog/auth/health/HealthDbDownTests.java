package com.lolog.auth.health;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

// 서버가 뜬 뒤 DB가 멈추면 503 DOWN이고, 오래 기다리지 않는다.
// 서버는 시작할 때 마이그레이션에 DB가 필요하므로, 띄운 다음 이 클래스의 DB 컨테이너만 멈춘다.
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class HealthDbDownTests {

	@Container
	@ServiceConnection
	static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:latest");

	@Container
	@ServiceConnection(name = "redis")
	@SuppressWarnings("resource")
	static GenericContainer<?> redis = new GenericContainer<>("redis:latest").withExposedPorts(6379);

	@Autowired
	MockMvc mvc;

	@Test
	void DB가_멈추면_503_DOWN이다() throws Exception {
		mvc.perform(get("/auth/health")).andExpect(status().isOk());
		postgres.stop();

		long start = System.nanoTime();
		mvc.perform(get("/auth/health"))
			.andExpect(status().isServiceUnavailable())
			.andExpect(jsonPath("$.status").value("DOWN"));
		assertThat((System.nanoTime() - start) / 1_000_000).isLessThan(5_000);
	}

}
