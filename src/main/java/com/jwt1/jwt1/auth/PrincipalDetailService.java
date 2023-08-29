package com.jwt1.jwt1.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.jwt1.jwt1.model.User;
import com.jwt1.jwt1.repository.UserRepository;

import lombok.RequiredArgsConstructor;

// http://localhost:8080/login 요청이 올 때 동작함
@Service
@RequiredArgsConstructor
public class PrincipalDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("=== PrincipalDetailsService의 loadUserByUsername() ===");
        User userEntity = userRepository.findByUsername(username);
        return new PrincipalDetails(userEntity);
    }

}
