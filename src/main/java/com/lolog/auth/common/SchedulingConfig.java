package com.lolog.auth.common;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

// 탈퇴 데이터 삭제 다시 부르기(UserDataDeleter)와 정지 알림 다시 부르기(SuspensionNotifier)에 쓴다.
@Configuration(proxyBeanMethods = false)
@EnableScheduling
public class SchedulingConfig {

}
