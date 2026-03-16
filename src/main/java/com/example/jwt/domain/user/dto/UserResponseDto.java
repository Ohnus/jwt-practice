package com.example.jwt.domain.user.dto;

import com.example.jwt.domain.user.entity.UserEntity;
import com.example.jwt.domain.user.entity.UserRole;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UserResponseDto {

    private Long id;
    private String username;
    private String role;

    public static UserResponseDto from(UserEntity userEntity) {
        return UserResponseDto.builder()
                .id(userEntity.getId())
                .username(userEntity.getUsername())
                .role(userEntity.getRole().toString())
                .build();
    }
}
