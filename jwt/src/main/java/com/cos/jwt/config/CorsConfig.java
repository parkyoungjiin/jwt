package com.cos.jwt.config;

import org.apache.catalina.filters.CorsFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

@Configuration
public class CorsConfig {

   @Bean
   public CorsFilter corsFilter() {
      UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
      CorsConfiguration config = new CorsConfiguration();
      
      config.setAllowCredentials(true); // 서버가 응답할 때 JSON을 자바스크립트에서 처리여부를 설정
      config.addAllowedOrigin("*"); // 모든 IP에 응답을 허용.
      config.addAllowedHeader("*"); // 모든 헤더에 응답을 허용.
      config.addAllowedMethod("*"); // 모든 메서드(GET, POST) 요청을 허용.
      
      source.registerCorsConfiguration("/api/**", config);
      return new CorsFilter();
   }

}
