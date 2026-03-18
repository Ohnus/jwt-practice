package com.example.jwt.jwt;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

public interface RefreshRepository extends JpaRepository<RefreshEntity, Long> {

    // refresh 토큰 유무 확인
    boolean existsByRefresh(String refresh);

    // refresh 토큰 삭제(user당 멀티 디바이스일 수도 있으니 토큰으로 확인, 삭제)
    void deleteByRefresh(String refresh);
}
