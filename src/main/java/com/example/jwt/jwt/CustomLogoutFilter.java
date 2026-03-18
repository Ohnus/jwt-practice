package com.example.jwt.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

@RequiredArgsConstructor
public class CustomLogoutFilter extends GenericFilterBean {

    private final JWTUtil jwtUtil;
    private final RefreshService refreshService;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        // 경로 체크
        String requestUri = request.getRequestURI();
        System.out.println("request URI: " + requestUri);
        if (!requestUri.equals("/logout")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 메서드 체크
        String requestMethod = request.getMethod();
        if (!requestMethod.equals("POST")) {
            filterChain.doFilter(request, response);
            return;
        }

        // refresh token 추출 및 null 체크
        String refreshToken = refreshService.getRefreshFromCookie(request);
        if (refreshToken == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        try {
            // 만료 및 위조 체크
            Claims claims = jwtUtil.getClaims(refreshToken);

            // 카테고리 체크
            String category = claims.get("category", String.class);
            if (!category.equals("refresh")) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            // DB 체크
            boolean ixExists = refreshService.isExists(refreshToken);
            if (!ixExists) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            // 로그아웃 진행
            // DB에서 리프레시 토큰 제거
            refreshService.removeRefreshEntity(refreshToken);

            // 쿠키 초기화
            response.addCookie(deleteCookie("refresh"));
            response.setStatus(HttpServletResponse.SC_OK);

        } catch (ExpiredJwtException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        } catch (Exception e) {
            response.setStatus((HttpServletResponse.SC_UNAUTHORIZED));
        }
    }

    // 쿠키 초기화 메서드
    public Cookie deleteCookie(String key) {
        Cookie cookie = new Cookie(key, null);
        cookie.setMaxAge(0);
        cookie.setPath("/");
        // cookie.setSecure(true); // Https일 경우 설정
        cookie.setHttpOnly(true); // JS로 해당 쿠키에 접근 못하도록 설정

        return cookie;
    }
}
