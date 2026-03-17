package com.example.jwt.domain.user.service;

import com.example.jwt.domain.user.dto.CustomUserDetails;
import com.example.jwt.domain.user.entity.UserEntity;
import com.example.jwt.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) {

        // DB에서 유저 조회
        UserEntity userEntity = userRepository.findByUsername(username);

        // 유저 조회되면 UserDetails에 담아서 AuthenticationManager가 검증
        if(userEntity != null) {

            return new CustomUserDetails(userEntity);
        }

        return null;
    }

}
