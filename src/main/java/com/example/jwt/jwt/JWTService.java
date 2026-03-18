package com.example.jwt.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JWTService {

    private final JWTUtil jwtUtil;
    private final RefreshService refreshService;

    // JWT Access Token reissue
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {

        // refresh token 추출
        String refreshToken = refreshService.getRefreshFromCookie(request);

        // refresh token null check
        if(refreshToken == null) {
            return new ResponseEntity<>("Refresh Token is null", HttpStatus.UNAUTHORIZED);
        }

        try {
            // refresh token 만료/위조 검증
            Claims claims = jwtUtil.getClaims(refreshToken);

            // 카테고리 검증
            String category = claims.get("category").toString();
            if(!category.equals("refresh")) {
                return new ResponseEntity<>("Invalid Refresh Token", HttpStatus.UNAUTHORIZED);
            }

            // DB에 Refresh 토큰 유무 확인
            boolean isExists = refreshService.isExists(refreshToken);
            if(!isExists) {
                return new ResponseEntity<>("Invalid Refresh Token", HttpStatus.UNAUTHORIZED);
            }

            // 새로운 access, refresh token 생성
            String username = claims.get("username").toString();
            String role = claims.get("role").toString();

            String newAccessToken = jwtUtil.createJwt("access", username, role, 1_000L * 60 * 10);
            String newRefreshToken = jwtUtil.createJwt("refresh", username, role, 1_000L * 60 * 60 * 24);

            // DB에서 기존 RefreshToken 삭제 및 새로운 토큰 저장
            refreshService.rotateRefreshToken(username, refreshToken, newRefreshToken, 1_000L * 60 * 60 * 24);

            // 응답 헤더에 발급
            response.setHeader("Authorization", "Bearer " + newAccessToken);
            response.addCookie(createCookie("refresh", newRefreshToken));

            return new ResponseEntity<>(HttpStatus.OK);

        } catch (ExpiredJwtException e) {
            return new ResponseEntity<>("Refresh Token is expired", HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            return new ResponseEntity<>("Invalid Refresh Token", HttpStatus.UNAUTHORIZED);
        }
    }

    // 쿠키 생성 메서드
    public Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60);
        cookie.setPath("/"); // 쿠키가 적용될 범위 설정
        // cookie.setSecure(true); // Https일 경우 설정
        cookie.setHttpOnly(true); // JS로 해당 쿠키에 접근 못하도록 설정

        return cookie;
    }

}
