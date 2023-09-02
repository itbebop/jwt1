package com.cors.jwt1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.web.filter.CorsFilter;

import com.cors.jwt1.config.jwt.JwtAuthenticationFilter;
import com.cors.jwt1.config.jwt.JwtAuthorizationFilter;
import com.cors.jwt1.filter.MyFilter3;
import com.cors.jwt1.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final UserRepository userRepository;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf(csrf -> csrf.disable());

        http.addFilterBefore(new MyFilter3(), SecurityContextHolderFilter.class); // -> Security filter 중 가장 처음에 나오는 필터
                                                                                  // -> 전에 나오도록 함
        // 처음에 addFilter -> securityFilter가 아니므로
        // before/after로 걸라고함, 굳이 securityFilter chain으로 걸 필요없이
        // FilterConfig, 각 customfilter 파일 만들어서 걸어줄 수 있다
        // 단 순서는 security filter가 먼저 실행된 후 custom filter가 실행됨
        http
                .sessionManagement(management -> management.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilter(corsFilter)// @CrossOrigin(인증없을때), 시큐리티 필터에 등록(인증필요할때)
                .httpBasic(basic -> basic.disable()) // id, pw 암호화 되도록

                .addFilter(new JwtAuthenticationFilter(authenticationConfiguration.getAuthenticationManager()))
                .addFilter(new JwtAuthorizationFilter(authenticationConfiguration.getAuthenticationManager(),
                        userRepository))
                .formLogin(login -> login.disable())
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();
        // 오류남
        // Unsatisfied dependency expressed through method 'setFilterChains'parameter 0
        // .authorizeRequests(requests -> requests
        // .antMatchers("/api/v1/user/**").access("hasRole('ROLE_USER')")
        // .antMatchers("/api/v1/manager/**").access("hasRole('ROLE_MANAGER')")
        // .antMatchers("/api/v1/admin/**").access("hasRole('ROLE_MANAGER')")
        // .anyRequest().permitAll());
        // 권한 체크안됨
        // .authorizeHttpRequests() // 인증 시작
        // .antMatchers("api/v1/user/**").hasAnyAuthority("ROLE_USER")
        // .antMatchers("api/v1/manager/**").hasAnyAuthority("ROLE_MANAGER")
        // .antMatchers("api/v1/admin/**").hasAuthority("ROLE_ADMIN")
        // .anyRequest().permitAll();

        return http.build();
    }

}
