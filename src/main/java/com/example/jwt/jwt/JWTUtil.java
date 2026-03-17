package com.example.jwt.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {

    // SecretKey, JwtParser 객체 생성 생성자 주입
    private final SecretKey secretKey;
    private final JwtParser jwtParser;

    public JWTUtil(@Value("${app.jwt.secret.key}") String key) {
        this.secretKey = Keys.hmacShaKeyFor(key.getBytes(StandardCharsets.UTF_8));
        // 검증에 사용할 키 설정 및 parser 생성
        this.jwtParser = Jwts.parser().verifyWith(secretKey).build();
    }

    // Claim 메서드 중복 제거
    private Claims getClaims(String token) {
        // 토큰을 실제로 파싱(JWT 구조 분해)하여 signature 검증, 만료 검사 및 파싱된 payload 호출
        return jwtParser.parseSignedClaims(token).getPayload();
    }

    public String getUsername(String token) {
        // payload에서 username 획득
        return getClaims(token).get("username", String.class);
    }

    public String getRole(String token) {
        // payload에서 role 획득
        return getClaims(token).get("role", String.class);
    }

    public boolean isExpired(String token) {
        // JWT payload의 exp 값을 현재 시간과 비교하여 만료 여부 확인
        // (단, parseSignedClaims 단계에서 이미 만료 시 ExpiredJwtException 발생 가능)
        return getClaims(token).getExpiration().before(new Date());
    }

    // JWT 생성
    public String createJwt(String username, String role, Long expiredMs) {

        return Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey)
                .compact();
    }
}
