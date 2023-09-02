package com.cors.jwt1.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cors.jwt1.config.auth.PrincipalDetails;
import com.cors.jwt1.model.User;
import com.cors.jwt1.repository.UserRepository;

/*  
시큐리티 filter 중 BasicAuthenticationFilter
권한이나 인증이 피룡한 특정 주소를 요청했을 때 타는 필터임
권한이나 인증이 필요한 주소가 아니라면 위 필터를 타지 않음
*/
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    // 인증이나 권한이 필요한 주소요청이 있을 때 이 필터를 타게 됨
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        System.out.println("=== 인증이나 권한이 필요한 주소 요청 ===");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader : " + jwtHeader);

        // header가 있는지 확인
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }
        // JWT 토큰을 검증하여 정상적인 사용자인지 확인
        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");

        String username = JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken).getClaim("username")
                .asString();
        // 서명이 정상적으로 됨
        if (username != null) { // username이 null이 아니란 것은 사용자이름이 정상 인증이 된 것
            System.out.println("=== username 정상 ===");
            User userEnity = userRepository.findByUsername(username);
            System.out.println("=== username in JwtAuthorizationFilter : " + userEnity.getUsername());

            // Jwt 토큰 서명을 통해서 서명이 정상이면
            // authentication 객체를 강제로 만듬(<> 로그인하여 정상적으로 만든 것이 아니라)
            PrincipalDetails principalDetails = new PrincipalDetails(userEnity);
            System.out.println(
                    "=== username by principalDetails in AuthorizationFilter : " + principalDetails.getUsername());
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails,
                    null, principalDetails.getAuthorities());
            // 강제로 시큐리티의 세션에 접근하여 세션에 Authentication 객체를 저장(세션을 만듬)
            // 이걸 만들어야 controller의 user 부분의 username이 나옴
            System.out.println("Authority in JwtAuthorizationFilter : " + principalDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);
        }

    }

}
