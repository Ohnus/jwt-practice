package com.example.jwt.domain.user.service;

import com.example.jwt.domain.user.dto.UserRequestDto;
import com.example.jwt.domain.user.entity.UserEntity;
import com.example.jwt.domain.user.entity.UserRole;
import com.example.jwt.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder bCryptPasswordEncoder;

    // 회원가입 로직
    @Transactional
    public void joinProcess(UserRequestDto userRequestDto) {

        boolean isExists = userRepository.existsByUsername(userRequestDto.getUsername());

        if(isExists) {
            throw new IllegalArgumentException("Username is already in use");
        }

        UserEntity userEntity = UserEntity.builder()
                .username(userRequestDto.getUsername())
                .password(bCryptPasswordEncoder.encode(userRequestDto.getPassword()))
                .role(UserRole.ROLE_ADMIN)
                .build();

        userRepository.save(userEntity);
    }

}
