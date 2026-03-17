package com.example.jwt.domain.user.dto;

import com.example.jwt.domain.user.entity.UserEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {

    // CustomUserDetailsService에서 사용하기 위해 UserEntity 객체 생성자 주입
    private final UserEntity userEntity;

    // role 반환
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        return List.of(
                new SimpleGrantedAuthority(userEntity.getRole().name())
        );
    }

    // password 반환
    @Override
    public String getPassword() {
        System.out.println("CustomUserDetails User name: " + userEntity.getUsername());
        System.out.println("CustomUserDetails User password: " + userEntity.getPassword());
        System.out.println("CustomUserDetails User role: " + userEntity.getRole().toString());
        return userEntity.getPassword();
    }

    // username 반환
    @Override
    public String getUsername() {
        return userEntity.getUsername();
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
