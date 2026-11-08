-- 회원. 탈퇴는 소프트 삭제(deleted_at)다(FR-AUTH-05).
-- id는 lolog-api 테이블의 user_id와 액세스 토큰의 sub로 쓴다.
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(254) NOT NULL,
    password_hash VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT ck_users_email_lower CHECK (email = lower(email))
);

-- 한 이메일에는 살아 있는 계정 하나만 둔다. 탈퇴한 계정의 이메일로는 다시 가입할 수 있다.
CREATE UNIQUE INDEX uk_users_email_active ON users (email) WHERE deleted_at IS NULL;

-- 회원에 연결한 소셜 계정(FR-AUTH-02, FR-AUTH-06). 탈퇴하면 회원과 함께 소프트 삭제한다.
CREATE TABLE social_accounts (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users (id),
    provider VARCHAR(10) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT ck_social_accounts_provider CHECK (provider IN ('KAKAO', 'GOOGLE', 'NAVER'))
);

-- 소셜 계정 하나는 살아 있는 회원 하나에만 붙는다.
CREATE UNIQUE INDEX uk_social_accounts_provider_user_active
    ON social_accounts (provider, provider_user_id) WHERE deleted_at IS NULL;
-- 회원 하나에는 회사마다 소셜 계정 하나만 붙는다.
CREATE UNIQUE INDEX uk_social_accounts_user_provider_active
    ON social_accounts (user_id, provider) WHERE deleted_at IS NULL;

COMMENT ON TABLE users IS '회원';
COMMENT ON COLUMN users.id IS '회원 ID-----lolog-api의 user_id, 액세스 토큰의 sub';
COMMENT ON COLUMN users.email IS '이메일-----소문자로 저장';
COMMENT ON COLUMN users.password_hash IS '비밀번호 BCrypt 해시-----소셜로만 가입했으면 NULL';
COMMENT ON COLUMN users.created_at IS '가입 시각';
COMMENT ON COLUMN users.deleted_at IS '탈퇴 시각-----NULL이면 살아 있는 회원';
COMMENT ON TABLE social_accounts IS '소셜 계정 연결';
COMMENT ON COLUMN social_accounts.user_id IS '회원 ID';
COMMENT ON COLUMN social_accounts.provider IS '회사-----KAKAO, GOOGLE, NAVER';
COMMENT ON COLUMN social_accounts.provider_user_id IS '그 회사의 사용자 ID';
COMMENT ON COLUMN social_accounts.created_at IS '연결 시각';
COMMENT ON COLUMN social_accounts.deleted_at IS '탈퇴 시각-----NULL이면 살아 있는 연결';
