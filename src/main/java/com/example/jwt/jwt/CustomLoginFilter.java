package com.example.jwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Date;

@RequiredArgsConstructor
public class CustomLoginFilter extends UsernamePasswordAuthenticationFilter {

    // Spring Security 라이브러리의 인터페이스 AuthenticationManager 타입 필드 생성
    private final AuthenticationManager authenticationManager;
    // 로그인 성공 시 JWT를 발급하기 위해 JWTUtil 생성자 주입
    private final JWTUtil jwtUtil;
    // JWTService 주입
    private final JWTService jwtService;
    // Refresh 주입
    private final RefreshService refreshService;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // 클라이언트 요청에서 username, password 추출
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        // 시큐리티에서 username과 password 검증하기 위해서는 token에 담아야 한다. 롤은 우선 null 처리
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        // token에 담긴 값을 자동으로 검증하기 위해 AuthenticationManager로 전달
        // UserDetailsService에서 DB를 거쳐 회원 정보 가져와서 User에 담아서 비교함
        return authenticationManager.authenticate(authToken);
    }

    // 로그인 성공 시 실행하는 메서드(여기서 JWT 다중 토큰 발급)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {

        // User 정보 호출
        String username = authentication.getName();
        String role = authentication.getAuthorities().iterator().next().toString();

        // 다중 토큰 생성 (ms * sec * min * hour)
        // access = 10분 / refresh = 24시간
        String accessToken = jwtUtil.createJwt("access", username, role, 5L * 60 * 10);
        String refreshToken = jwtUtil.createJwt("refresh", username, role, 1_000L * 60 * 60 * 24);

        // 기존 Refresh 토큰 삭제 및 새 토큰 DB 저장
        refreshService.addRefreshEntity(username, refreshToken, 1_000L * 60 * 60 * 24);

        // 헤더 응답
        response.setHeader("Authorization", "Bearer " + accessToken);
        response.addCookie(jwtService.createCookie("refresh", refreshToken));
        response.setStatus(HttpStatus.OK.value());
    }

    // 로그인 실패 시 실행하는 메서드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {

        // 로그인 실패 시 401 응답 코드 반환
        response.setStatus(401);
    }

}
