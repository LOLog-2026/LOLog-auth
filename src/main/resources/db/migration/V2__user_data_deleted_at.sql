-- 탈퇴한 회원의 데이터를 lolog-api가 다 지웠는지(DELETE /internal/users/{id}가 204를 줬는지) 적는다.
-- 탈퇴했는데(deleted_at) 아직 비어 있으면 204가 올 때까지 다시 부른다(LOLog-docs PR #28).
ALTER TABLE users ADD COLUMN data_deleted_at TIMESTAMPTZ;

CREATE INDEX idx_users_data_delete_pending ON users (id) WHERE deleted_at IS NOT NULL AND data_deleted_at IS NULL;

COMMENT ON COLUMN users.data_deleted_at IS 'lolog-api 데이터 삭제 완료 시각-----탈퇴했는데 NULL이면 다시 부를 대상';
