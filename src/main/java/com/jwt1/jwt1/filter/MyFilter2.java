package com.jwt1.jwt1.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class MyFilter2 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        System.out.println("###필터2###");
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // 필터가 웹 컨테이너에서 삭제될 때 호출
    }
}
