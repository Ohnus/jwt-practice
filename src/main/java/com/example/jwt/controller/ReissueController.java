package com.example.jwt.controller;

import com.example.jwt.jwt.JWTUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class ReissueController {

    private final JWTUtil jwtUtil;

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {

        // 쿠키에서 refresh token 추출
        Cookie[] cookies = request.getCookies();

        String refreshToken = null;
        for(Cookie cookie : cookies) {
           if(cookie.getName().equals("refresh")) {
               refreshToken = cookie.getValue();
           }
        }

        if(refreshToken == null) {
            return new ResponseEntity<>("Refresh Token is null", HttpStatus.UNAUTHORIZED);
        }

        try {
            // refresh token 만료/위조 검증
            Claims claims = jwtUtil.getClaims(refreshToken);

            // 카테고리 검증
            String category = claims.get("category").toString();
            if(!category.equals("refresh")) {
                return new  ResponseEntity<>("Invalid Refresh Token", HttpStatus.UNAUTHORIZED);
            }

            // 새로운 access token 생성
            String username = claims.get("username").toString();
            String role = claims.get("role").toString();

            String newAccessToken = jwtUtil.createJwt("access", username, role, 1_000L * 60 * 10);

            // 응답 헤더에 발급
            response.setHeader("Authorization", "Bearer " + newAccessToken);

            return new ResponseEntity<>(HttpStatus.OK);

        } catch (ExpiredJwtException e) {
            return new ResponseEntity<>("Refresh Token is expired", HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            return new ResponseEntity<>("Invalid Refresh Token", HttpStatus.UNAUTHORIZED);
        }
    }
}
