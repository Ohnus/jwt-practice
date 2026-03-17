package com.example.jwt.domain.user.repository;

import com.example.jwt.domain.user.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    // 유저 존재 확인
    Boolean existsByUsername(String username);

    // 유저 조회
    UserEntity findByUsername(String username);
}
