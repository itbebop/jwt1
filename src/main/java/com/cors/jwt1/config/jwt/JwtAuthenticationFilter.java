package com.cors.jwt1.config.jwt;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.cors.jwt1.config.auth.PrincipalDetails;
import com.cors.jwt1.dto.LoginRequestDto;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에서 UsernamePassordAuthenticationFilter가 있음
// login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 동작을 함
// 그러나 security config에서 formlogin을 disable해서 작동 안함
// 그래서 이 필터를 다시 security filter에 등록함 (addfilter.. JwtAuthenticationFilter)
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // @Bean
    // public AuthenticationManager
    // authenticationManager(AuthenticationConfiguration
    // authenticationConfiguration)
    // throws Exception {
    // System.out.println("로그인 시도중");

    // //1. username, password 받아서
    // //2. 정상인지 로그인 시도를 해보는 것. authenticationManager로 로그인 시도를 하면
    // // PrincipalDetailsService가 호출됨
    // // 그러면 UserDetails의 loadUserByUsername이 실행되는 것
    // // 3. principal details를 세션에 담고 (권한 관리를 위해서)
    // // 4. JWT토큰을 만들어서 응답해주면 됨
    // return authenticationConfiguration.getAuthenticationManager();
    // }
    // Authentication 객체 만들어서 리턴 => 의존 : AuthenticationManager

    // 인증 요청시에 실행되는 함수 => /login

    // Authentication 객체 만들어서 리턴 => 의존 : AuthenticationManager
    // 인증 요청시(로그인 요청시)에 실행되는 함수 => /login
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        System.out.println("JwtAuthenticationFilter : 진입");
        // BufferedReader br = request.getReader();
        // String input = null;
        // while ((input = br.readLine()) != null)
        // System.out.println("==============input : " + input);

        try {
            // request에 있는 username과 password를 파싱해서 자바 Object로 받기
            ObjectMapper om = new ObjectMapper(); // json 데이터를 파싱해줌
            LoginRequestDto loginRequestDto = null;

            loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class);

            System.out.println("loginRequestDto in JwtAuthenticationFilter : " + loginRequestDto);

            // username과 password로 유저네임패스워드 토큰 생성
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    loginRequestDto.getUsername(),
                    loginRequestDto.getPassword());

            System.out.println("============================ 토큰생성완료");

            // authenticate() 함수가 호출 되면 인증 프로바이더가 유저 디테일 서비스의
            // loadUserByUsername(토큰의 첫번째 파라메터) 를 호출하고
            // UserDetails를 리턴받아서 토큰의 두번째 파라메터(credential)과
            // UserDetails(DB값)의 getPassword()함수로 비교해서 동일하면
            // Authentication 객체를 만들어서 필터체인으로 리턴해준다.

            // Tip: 인증 프로바이더의 디폴트 서비스는 UserDetailsService 타입
            // Tip: 인증 프로바이더의 디폴트 암호화 방식은 BCryptPasswordEncoder
            // 결론은 인증 프로바이더에게 알려줄 필요가 없음.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // id, pw가 출력되는 건 authentication 객체가 session영역에 저장된 것 => 즉, 로그인이 되었다는 것
            PrincipalDetails principalDetailis = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("Authentication : " + principalDetailis.getUser().getUsername());
            System.out.println("==============================1");

            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("==============================2");
        return null;
    }
}
