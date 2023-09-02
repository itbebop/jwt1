package com.cors.jwt1.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.cors.jwt1.config.auth.PrincipalDetails;
import com.cors.jwt1.model.User;
import com.cors.jwt1.repository.UserRepository;

@RestController
public class RestApiController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public RestApiController(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @GetMapping("home")
    public String home() {
        return "<h1>home</h1>";
    }

    @PostMapping("token")
    public String token() {
        return "<h1>token</h1>";
    }

    @PostMapping("join")
    public String join(@RequestBody User user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입완료";
    }

    // user/manager/admin 권한만 접근 가능
    @PostMapping("/api/v1/user")
    // public String user() {
    public String user(Authentication authentication) {
        PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("Username in controller : " + principal.getUsername()); //
        System.out.println("Authority in controller : " + principal.getAuthorities()); //
        // Session이 만들어지면 이게 나옴
        return "user";
    }

    // manager/admin 권한만 접근 가능
    @PostMapping("/api/v1/manager")
    public String manager() {
        return "manager";
    }

    // admin 권한만 접근 가능
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @PostMapping("/api/v1/admin")
    public String admin() {
        return "admin";
    }

}
