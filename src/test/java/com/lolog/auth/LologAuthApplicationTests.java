package com.lolog.auth;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

// 실제 PostgreSQL에 Flyway 마이그레이션을 적용하고, 엔티티와 테이블이 맞는지(ddl-auto: validate)까지 확인한다.
@SpringBootTest
@Import(TestContainers.class)
class LologAuthApplicationTests {

	@Test
	void contextLoads() {
	}

}
