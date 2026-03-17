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
import java.io.PrintWriter;
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
        System.out.println("JWTFilter Access Token: " + token);

        try {
            // 이미 인증된 경우 통과
            if(SecurityContextHolder.getContext().getAuthentication() != null) {
                filterChain.doFilter(request, response);
                return;
            }

            // 만료 및 서명 위조 검사(예외 터질 시 catch 실행)
            Claims claims = jwtUtil.getClaims(token);

            // Access 토큰인지 확인
            String tokenCategory = claims.get("category").toString();
            if(!tokenCategory.equals("access")) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json;charset=utf-8");
                PrintWriter writer = response.getWriter();
                writer.write("Not Access Token");
                writer.flush();

                return;
            }

            // 유저 정보 추출
            String username = claims.get("username",  String.class);
            String role = claims.get("role",String.class);

            // 인증 객체 생성
            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(username, null, List.of(new SimpleGrantedAuthority(role)));

            // SecurityContextHolder 등록
            SecurityContextHolder.getContext().setAuthentication(authToken);

        } catch (ExpiredJwtException e) {
            // response status code
            System.out.println("Token expired");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            // response body
            PrintWriter writer = response.getWriter();
            writer.write("Access Token Expired");
            writer.flush();

            return;
        } catch (Exception e) {
            // 위조 또는 잘못된 토큰
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            PrintWriter writer = response.getWriter();
            writer.write("Invalid Token");
            writer.flush();

            return;
        }

        // 끝났으면 다음 필터로 패스
        filterChain.doFilter(request, response);
    }
}
