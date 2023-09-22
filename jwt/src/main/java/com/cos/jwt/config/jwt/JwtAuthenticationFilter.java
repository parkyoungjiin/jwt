package com.cos.jwt.config.jwt;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties.Jwt;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음.
// UsernamePasswordAuthenticationFilter는 /login 요청 시 username, password를 post로 전송하면 동작한다.
// formLogin.disable로 인해 동작하지 않음.
// UsernamePasswordAuthenticationFilter 필터를 SecurityConfig에 등록하면 해결 된다.

@RequiredArgsConstructor // => authenticationManager를 파라미터로 받는 생성자를 만들어준다.
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
	private final AuthenticationManager authenticationManager;
	
	// /login 요청이 발생하면 로그인 시도를 위해 실행되는 함수 (attemptAuthentication)
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("jwtAuthenticationFilter : 로그인 시도");
		try {
//			BufferedReader br = request.getReader();
//			System.out.println(request.getReader());
//			
//			String input = null;
//			while((input = br.readLine()) != null){
//				System.out.println("input:" + input);
//			}
			
			ObjectMapper om = new ObjectMapper();
			User user = om.readValue(request.getInputStream(), User.class);
			System.out.println(user);
			
			//토큰 제작(form 로그인 시 자동으로 처리되지만 jwt이기에 토큰을 직접 생성)
			UsernamePasswordAuthenticationToken authenticationToken =
					new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			System.out.println("authenticationToken발급 ");
			//PrincipalDetailsService의 loadUserByUsername() 함수 실행.
			Authentication authentication =
					authenticationManager.authenticate(authenticationToken);
			System.out.println("2authentication");
			//authentication 객체가 session 영역에 저장된다. =>  로그인이 된 것.
			PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal(); //principal 객체를 리턴함.
			System.out.println("principalDetails");
			System.out.println(principalDetails.getUser().getUsername() + "님이 로그인하셨습니다.");
					
			// JWT 토큰
			return authentication; // 로그인 성공 시 authentication이 세션에 저장된다. 

		} catch (IOException e) {
			e.printStackTrace();
		}
		
		
		return null;
	} //try 끝
	
	// attemptAuthentication 실행 후 인증이 정상적으로 된 경우 successfulAuthentication 함수가 실행된다.
	// -> JWT token을 successfulAuthentication 함수에서 request를 요청한 사용자에게 JWT 토큰을 response 하면 된다.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication 함수 실행 : 인증 완료");
		
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
		
		//토큰 제작(라이브러리 이용)
		// Hash 암호화 방식.(secret 키를 갖고 있어야 함.)
		String jwtToken = JWT.create()
				.withSubject(principalDetails.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512(JwtProperties.SECRET));
		
		//Response Header에 token을 담아서 리턴.
		response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
	}
}// 함수 끝
