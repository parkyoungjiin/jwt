package com.cos.jwt.filter;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.tomcat.util.http.parser.Authorization;

public class MyFilter1 implements Filter{

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// 요청, 응답 객체를 다운 캐스팅.
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		
		if(req.getMethod().equals("POST")) {
			System.out.println("POST 요청");
			String headerAuth = req.getHeader("Authorization");
			System.out.println("headerAuth: " + headerAuth);
			
			if(headerAuth.equals("cos")) {
				System.out.println("인증 성공");
				chain.doFilter(req, res);
			}else {
				PrintWriter out = res.getWriter();
				out.println("인증 실패");
			}
		}else {
			System.out.println("POST가 아닌 다른 메서드");
		}
		
		System.out.println("필터1");
		chain.doFilter(request, response); // 다음 필터로 이동
	}
	
}
