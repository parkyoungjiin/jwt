package com.cos.jwt.config;

import javax.servlet.FilterChain;

import org.apache.catalina.filters.CorsFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.cos.jwt.config.jwt.jwtAuthenticationFilter;


@Configuration
@EnableWebSecurity // 시큐리티 활성화 및 웹 보안 설정 구성에 사용된다.
public class SecurityConfig{
    private final CorsFilter corsFilter = new CorsFilter();

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
	@Autowired
	private CorsConfig corsConfig;
	
	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		return http
	            .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
				.csrf().disable()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 사용하지 않는다는 설정.
				.and()
				.formLogin().disable() //jwt이기에 아이디, 비밀번호를 통한 로그인을 진행하지 않음.
				.httpBasic().disable() // 
				.apply(new MyCustomDsl()) // 커스텀 필터 등록
				.and()
				.authorizeRequests(authroize -> authroize.antMatchers("/api/v1/user/** or /h2-console/**") // user에 대한 경로의 접근 권한 설정
						.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
						.antMatchers("/api/v1/manager/**") // manager에 대한 경로의 접근 권한 설정
						.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
						.antMatchers("/api/v1/admin/**") // admin에 대한 경로의 접근 권한 설정
						.access("hasRole('ROLE_ADMIN')")
						.anyRequest().permitAll())
				.build();

	}
	
	public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
		@Override
		public void configure(HttpSecurity http) throws Exception {
			AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
			http
					.addFilter(corsConfig.corsFilter()) //corsFilter 설정
					.addFilter(new jwtAuthenticationFilter(authenticationManager));

		}
	}
	

	
}
