package com.cors.jwt1.config.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.cors.jwt1.model.User;

import lombok.Data;

@Data
public class PrincipalDetails implements UserDetails {
    private User user;

    public PrincipalDetails(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        for (String auth : user.getRoleList()) {
            authorities.add(new SimpleGrantedAuthority(auth));
        }
        // user.getRoleList().forEach(r -> {
        // authorities.add(() -> r);
        // System.out.println("===== RoleList() : " + user.getRoleList());
        // });
        return authorities;
    }
    // 아래로 넣으려고 하면 orverride안된 함수 있다고 에러남
    // public ArrayList<GrantedAuthority> loadUserAuthorities(User user) {

    // List<String> authorities = user.getRoleList();
    // ArrayList<GrantedAuthority> grantedAuthorities = new ArrayList<>();

    // for (String auth: authorities) {
    // grantedAuthorities.add(new SimpleGrantedAuthority(auth));
    // }

    // return grantedAuthorities;
    // }

    public User getUser() {
        return user;
    }

    @Override
    public String getPassword() {

        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
