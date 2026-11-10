package com.lolog.auth;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.postgresql.PostgreSQLContainer;

// 테스트용 PostgreSQL·Redis. 테스트 클래스에 @Import(TestContainers.class)로 붙인다. Docker가 켜져 있어야 한다.
// lolog-api의 compose.yaml과 같은 이미지를 쓴다. 메일은 실제로 보내지 않고 FakeMailer로 받는다.
@TestConfiguration(proxyBeanMethods = false)
@Import(FakeMailer.Config.class)
public class TestContainers {

	@Bean
	@ServiceConnection
	PostgreSQLContainer postgres() {
		return new PostgreSQLContainer("postgres:latest");
	}

	@Bean
	@ServiceConnection(name = "redis")
	GenericContainer<?> redis() {
		return new GenericContainer<>("redis:latest").withExposedPorts(6379);
	}

}
