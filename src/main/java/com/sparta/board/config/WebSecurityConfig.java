package com.sparta.board.config;


import com.sparta.board.jwt.JwtUtil;
import com.sparta.board.security.JwtAuthenticationFilter;
import com.sparta.board.security.JwtAuthorizationFilter;
import com.sparta.board.security.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity // Spring Security 지원을 가능하게 함
@RequiredArgsConstructor
public class WebSecurityConfig {

    private final JwtUtil jwtUtil; // 끝 // JwtUtil은 JWT 토큰을 생성하고 검증하는 역할을 한다.
    private final UserDetailsServiceImpl userDetailsService; //끝
    private final AuthenticationConfiguration authenticationConfiguration; //끝

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }// 비밀번호 암호화

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();//인증을 처리하는 AuthenticationManager를 빈으로 등록한다.
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtUtil);
        filter.setAuthenticationManager(authenticationManager(authenticationConfiguration));
        return filter;
    }

    @Bean
    public JwtAuthorizationFilter jwtAuthorizationFilter() {//JwtAuthorizationFilter를 빈으로 등록한다. //JwtAuthorizationFilter는 OncePerRequestFilter를 상속받는다. //   OncePerRequestFilter는 요청이 들어올 때마다 실행되는 필터이다. //   JwtAuthorizationFilter는 요청이 들어올 때마다 JWT 토큰의 유효성을 검사한다. //   JWT 토큰이 유효하면, 해당 토큰에 담겨있는 정보를 이용하여 사용자 인증을 처리한다. //   사용자 인증이 처리되면, SecurityContext에 Authentication 객체를 저장한다. //   SecurityContext는 SecurityContextHolder를 통해 언제든지 접근할 수 있다. //   SecurityContextHolder는 SecurityContext를 저장하는 역할을 한다.
        return new JwtAuthorizationFilter(jwtUtil, userDetailsService);//   // JwtAuthorizationFilter는 JWT 토큰의 유효성을 검사하고, 사용자 인증을 처리한다.
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {//SecurityFilterChain를 빈으로 등록한다. //SecurityFilterChain는 Spring Security의 필터들을 관리하는 역할을 한다. //   Spring Security의 필터들은 SecurityFilterChain을 통해 관리된다.
        // CSRF 설정
        http.csrf((csrf) -> csrf.disable());

        // 기본 설정인 Session 방식은 사용하지 않고 JWT 방식을 사용하기 위한 설정
        http.sessionManagement((sessionManagement) ->
                sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        http.authorizeHttpRequests((authorizeHttpRequests) ->
                authorizeHttpRequests
                        .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll() // resources 접근 허용 설정
                        .requestMatchers("/").permitAll() // 메인 페이지 요청 허가
                        .requestMatchers("/api/auth/**").permitAll() // '/api/auth/'로 시작하는 요청 모두 접근 허가
                        .anyRequest().authenticated() // 그 외 모든 요청 인증처리
        );

        http.formLogin(AbstractHttpConfigurer::disable); // 폼 로그인 비활성화

        // 필터 관리
        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(jwtAuthorizationFilter(), JwtAuthenticationFilter.class);

        return http.build();
    }
}