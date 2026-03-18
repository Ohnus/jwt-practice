package com.example.jwt.jwt;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

@Service
@RequiredArgsConstructor
@Transactional(readOnly=true)
public class RefreshService {

    private final RefreshRepository refreshRepository;

    // Refresh 토큰 DB 저장 메서드
    @Transactional
    public void addRefreshEntity(String username, String refreshToken, Long expiration) {

        Date expirationDate = new Date(System.currentTimeMillis() + expiration);

        RefreshEntity refreshEntity = RefreshEntity.builder()
                .username(username)
                .refresh(refreshToken)
                .expiration(expirationDate.toString())
                .build();

        refreshRepository.save(refreshEntity);
    }

    // Refresh Token 삭제
    @Transactional
    public void removeRefreshEntity(String refreshToken) {
        refreshRepository.deleteByRefresh(refreshToken);
    }

    // Refresh Rotate(삭제+수정 원자성 위해 한 트랜잭션으로)
    @Transactional
    public void rotateRefreshToken(String username, String refreshToken, String newRefreshToken, Long expiration) {
        refreshRepository.deleteByRefresh(refreshToken);
        addRefreshEntity(username, newRefreshToken, expiration);
    }

    // Refresh Token 유뮤 체크
    public boolean isExists(String refreshToken) {
        return refreshRepository.existsByRefresh(refreshToken);
    }

    // refresh token 추출
    public String getRefreshFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        String refreshToken = null;
        for(Cookie cookie : cookies) {
            if(cookie.getName().equals("refresh")) {
                refreshToken = cookie.getValue();
            }
        }

        return refreshToken;
    }
}
