package com.jwt1.jwt1.config;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
@Component
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true); // 내 서버가 응답을 할 때 json을 자바스크립트에서 처리할 수 있게 할 지를 설정
        config.addAllowedOrigin("*"); // 모든 ip에 응답 허용
        config.addAllowedHeader("*");// 모든 header에 응답 허용
        config.addAllowedMethod("*");// 모든 post,get,put,delete,patch에 응답 허용
        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);
    }
}
