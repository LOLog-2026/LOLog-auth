-- 소셜 로그인에서 카카오를 뺐다. 카카오 이메일 동의항목에 비즈 앱 심사가 필요해서다(LOLog-docs PR #35).
-- 카카오 연결은 만든 적이 없어(로그인 기능 전) 지울 행이 없다.
ALTER TABLE social_accounts DROP CONSTRAINT ck_social_accounts_provider;
ALTER TABLE social_accounts ADD CONSTRAINT ck_social_accounts_provider CHECK (provider IN ('GOOGLE', 'NAVER'));

COMMENT ON COLUMN social_accounts.provider IS '회사-----GOOGLE, NAVER';
