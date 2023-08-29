package com.jwt1.jwt1.filter;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        System.out.println("###필터3###");
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        // 토큰 특정값이면 인증하고, 아니면 진입조차 못하게 할 것
        /*
         * 즉 토큰 검증 절차를 만들면 되는데,
         * ID, PW 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그 토큰으로 응답을 해줌
         * 요청할 때마다 header에 Authorization에 value값으로 토큰을 가져오면
         * 이 토큰이 내가 만든 토큰이 맞는지만 검증하면 됨
         */

        // req.setCharacterEncoding("UTF-8");
        // System.out.println(req.getMethod());
        if (req.getMethod().equals("POST")) {
            System.out.println("=====Post 요청됨=====");
            String headerAuth = req.getHeader("Authorization");
            System.out.println("headerAuth : " + headerAuth);
            if (headerAuth.equals("cors")) { // headerAuth는 한글 안됨
                chain.doFilter(req, res);
            } else {
                PrintWriter out = res.getWriter();
                out.println("인증안됨");
            }
        }
    }

    @Override
    public void destroy() {
        // 필터가 웹 컨테이너에서 삭제될 때 호출
    }
}
