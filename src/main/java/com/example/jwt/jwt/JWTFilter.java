package com.example.jwt.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // request에서 헤더의 Authorization key 추출
        String authorization = request.getHeader("Authorization");

        // authorization 체크, 없으면 통과(비로그인으로 가능한 다른 API 접근하도록)
        if(authorization == null || !authorization.startsWith("Bearer ")) {
            System.out.println("Token null");
            filterChain.doFilter(request, response);
            return;
        }

        // 토큰 추출
        String token = authorization.substring(7);
        System.out.println("JWTFilter token: " + token);

        try {
            // 이미 인증된 경우 통과
            if(SecurityContextHolder.getContext().getAuthentication() != null) {
                filterChain.doFilter(request, response);
                return;
            }

            // 만료 및 서명 위조 검사(예외 터질 시 catch 실행)
            Claims claims = jwtUtil.getClaims(token);

            // 유저 정보 추출
            String username = claims.get("username",  String.class);
            String role = claims.get("role",String.class);

            // 인증 객체 생성
            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(username, null, List.of(new SimpleGrantedAuthority(role)));

            // SecurityContextHolder 등록
            SecurityContextHolder.getContext().setAuthentication(authToken);

        } catch (ExpiredJwtException e) {
            // 만료 토큰, 추후 refresh 확장 가능
            System.out.println("Token expired");
            request.setAttribute("exception", "expired token");
        } catch (Exception e) {
            // 위조 또는 잘못된 토큰
            System.out.println("Invalid token");
            request.setAttribute("exception", "Invalid token");
        }

        // 끝났으면 다음 필터로 패스
        filterChain.doFilter(request, response);
    }
}
