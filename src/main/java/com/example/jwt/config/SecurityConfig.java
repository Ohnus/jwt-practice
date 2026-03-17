package com.example.jwt.config;

import com.example.jwt.jwt.CustomLoginFilter;
import com.example.jwt.jwt.JWTFilter;
import com.example.jwt.jwt.JWTUtil;
import lombok.RequiredArgsConstructor;
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

@Configuration
@EnableWebSecurity(debug = true)
@RequiredArgsConstructor
public class SecurityConfig {

    // authenticationManager 메서드에서 사용할 AuthenticationConfiguration 객체 생성자 주입
    private final AuthenticationConfiguration authConfiguration;
    // LoginFilter에서 JWTUtil 사용하기 위해 JWTUtil 주입
    private final JWTUtil jwtUtil;

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

        // CSRF disable
        http.csrf(csrf -> csrf.disable());

        // Form 로그인 방식 disable
        http.formLogin((auth) -> auth.disable());

        // http basic 방식 disable
        http.httpBasic((auth) -> auth.disable());

        // 경로별 인가 작업
        http.authorizeHttpRequests((auth) -> auth
                .requestMatchers("/", "/join", "/login").permitAll()
                .requestMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated());

        // JWTFilter 추가
        http.addFilterBefore(new JWTFilter(jwtUtil), CustomLoginFilter.class);

        // new로 생성자를 만들어서 넣게 된 커스텀 로그인 필터는 AuthenticationManager, JWTUtil을 인자로 주입 받음
        http.addFilterAt(new CustomLoginFilter(authenticationManager(), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        // 세션 설정
        http.sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
