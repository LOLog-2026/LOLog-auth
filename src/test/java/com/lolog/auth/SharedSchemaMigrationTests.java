package com.lolog.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

// 배포에서는 lolog-api와 같은 스키마를 쓴다(deployment.md 4장). lolog-api가 먼저 마이그레이션해
// 테이블이 이미 있어도, 인증 마이그레이션이 V1부터 적용되고 lolog-api의 이력 테이블은 건드리지 않는지 확인한다.
@Testcontainers
class SharedSchemaMigrationTests {

	@Container
	static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:latest");

	@Test
	void 메인_백엔드_테이블이_먼저_있어도_V1부터_적용된다() throws Exception {
		try (Connection c = connect(); Statement s = c.createStatement()) {
			// lolog-api가 먼저 만든 상태를 흉내 낸다.
			s.execute("CREATE TABLE cards (id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL)");
			s.execute("CREATE TABLE flyway_schema_history_api (installed_rank INT PRIMARY KEY)");
		}

		// application.yml의 spring.flyway 설정과 같은 값
		Flyway.configure()
			.dataSource(postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword())
			.table("flyway_schema_history_auth")
			.baselineOnMigrate(true)
			.baselineVersion("0")
			.load()
			.migrate();

		try (Connection c = connect(); Statement s = c.createStatement()) {
			assertThat(count(s, "SELECT count(*) FROM information_schema.tables WHERE table_name IN ('users', 'social_accounts')"))
				.isEqualTo(2);
			assertThat(count(s, "SELECT count(*) FROM flyway_schema_history_auth WHERE version = '1' AND success"))
				.isEqualTo(1);
			assertThat(count(s, "SELECT count(*) FROM flyway_schema_history_api")).isZero();
		}
	}

	private static Connection connect() throws Exception {
		return DriverManager.getConnection(postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword());
	}

	private static long count(Statement s, String sql) throws Exception {
		try (ResultSet rs = s.executeQuery(sql)) {
			rs.next();
			return rs.getLong(1);
		}
	}

}
