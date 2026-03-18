package com.example.jwt.config;

import com.example.jwt.jwt.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.apache.tomcat.util.file.ConfigurationSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebSecurity(debug = true)
@RequiredArgsConstructor
public class SecurityConfig {

    // authenticationManager 메서드에서 사용할 AuthenticationConfiguration 객체 생성자 주입
    private final AuthenticationConfiguration authConfiguration;
    // LoginFilter에서 JWTUtil 사용하기 위해 JWTUtil 주입
    private final JWTUtil jwtUtil;
    // JWTService 주입
    private final JWTService jwtService;
    // Refresh 주입
    private final RefreshService refreshService;

    // AuthenticationManager는 Spring Security 내부에서 AuthenticationConfiguration를 통해 만드는 객체
    // LoginFilter 등에서 사용하기 위해 Bean으로 등록
    @Bean
    public AuthenticationManager authenticationManager() throws Exception {

        return authConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // CORS 설정
        http.cors(cors -> cors.configurationSource(corsConfigurationSource()));

        // CSRF disable
        http.csrf(csrf -> csrf.disable());

        // Form 로그인 방식 disable
        http.formLogin((auth) -> auth.disable());

        // http basic 방식 disable
        http.httpBasic((auth) -> auth.disable());

        // 경로별 인가 작업
        http.authorizeHttpRequests((auth) -> auth
                .requestMatchers("/", "/join", "/login", "/reissue").permitAll()
                .requestMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated());

        // JWTFilter 추가
        http.addFilterBefore(new JWTFilter(jwtUtil), CustomLoginFilter.class);

        // new로 생성자를 만들어서 넣게 된 커스텀 로그인 필터는 AuthenticationManager, JWTUtil을 인자로 주입 받음
        http.addFilterAt(new CustomLoginFilter(authenticationManager(), jwtUtil, jwtService, refreshService), UsernamePasswordAuthenticationFilter.class);

        // 로그아웃 필터 추가
        http.addFilterBefore(new CustomLogoutFilter(jwtUtil, refreshService), LogoutFilter.class);

        // 세션 설정
        http.sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        // 프론트 주소
        config.setAllowedOrigins(List.of("http://localhost:3000"));

        // 허용 메서드
        // CORS는 실제 요청 전에 Preflight 요청(OPTIONS) 날리므로 포함 필수
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));

        // 모든 헤더 허용
        config.setAllowedHeaders(List.of("*"));

        // 인증정보 포함 (JWT / 쿠키)
        config.setAllowCredentials(true);

        // 노출할 헤더 (JWT Authorization)
        // 브라우저는 기본적으로 Authorization 헤더를 JS에서 못 읽으므로 설정
        config.setExposedHeaders(List.of("Authorization"));

        // 해당 url에 대해 config CORS 정책 사용
        UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
        src.registerCorsConfiguration("/**", config);

        return src;
    }
}
