package com.cos.jwt.config.jwt;

public interface JwtProperties {
	String SECRET = "cos";
	String TOKEN_PREFIX = "Bearer ";
	int EXPIRATION_TIME = 864000000;
	String HEADER_STRING = "Authorization";
}
