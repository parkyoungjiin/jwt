package com.cos.jwt.jwt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음.
// UsernamePasswordAuthenticationFilter는 /login 요청 시 username, password를 post로 전송하면 동작한다.
// formLogin.disable로 인해 동작하지 않음.
// UsernamePasswordAuthenticationFilter 필터를 SecurityConfig에 등록하면 해결 된다.

@RequiredArgsConstructor // => authenticationManager를 파라미터로 받는 생성자를 만들어준다.
public class jwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
	private final AuthenticationManager authenticationManager;
	
	
	// /login 요청이 발생하면 로그인 시도를 위해 실행되는 함수 (attemptAuthentication)
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("jwtAuthenticationFilter : 로그인 시도");
		return super.attemptAuthentication(request, response);
	}
}
