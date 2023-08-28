package com.jwt1.jwt1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

import com.jwt1.jwt1.filter.MyFilter1;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.addFilterBefore(new MyFilter1(), BasicAuthenticationFilter.class); // 처음에 addFilter -> securityFilter가 아니므로
                                                                                // before/after로 걸라고함
        http.csrf(csrf -> csrf.disable());
        http
                .sessionManagement(management -> management.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilter(corsFilter)// @CrossOrigin(인증없을때), 시큐리티 필터에 등록(인증필요할때)
                .httpBasic(basic -> basic.disable()) // id, pw 암호화 되도록
                .formLogin(login -> login.disable())
                .authorizeHttpRequests() // 인증 시작
                .antMatchers("/api/v1/user/**").hasAuthority("ROLE_USER, ROLE_MANAGER, ROLE_ADMIN")
                .antMatchers("api/v1/manager/**").hasAuthority("ROLE_MANAGER, ROLE_ADMIN")
                .antMatchers("api/v1/admin/**").hasAuthority("ROLE_ADMIN")
                .anyRequest().permitAll();

        return http.build();
    }

}
