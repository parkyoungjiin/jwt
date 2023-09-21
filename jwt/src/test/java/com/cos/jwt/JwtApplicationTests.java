package com.cos.jwt;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.cos.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@SpringBootTest
@RequiredArgsConstructor
class JwtApplicationTests {

	// create (생성) 테스트
	@Autowired
	private final UserRepository userRepository;
	
	
	
	
	@Test
	void contextLoads() {
	}

}
