package com.sparta.board.security;

import com.sparta.board.jwt.JwtUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j(topic = "JWT 검증 및 인가")
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsServiceImpl userDetailsService;

    public JwtAuthorizationFilter(JwtUtil jwtUtil, UserDetailsServiceImpl userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain filterChain) throws ServletException, IOException {

        String tokenValue = jwtUtil.getTokenFromRequest(req);

        if (StringUtils.hasText(tokenValue)) { // 토큰이 있는지 확인

            if (!jwtUtil.validateToken(tokenValue)) {//토큰이 유효한지 확인
                log.error("Token Error");
                return;
            }

            Claims info = jwtUtil.getUserInfoFromToken(tokenValue);//토큰에서 정보를 가져온다.

            try {
                setAuthentication(info.getSubject());//인증을 처리한다.
            } catch (Exception e) {
                log.error(e.getMessage());//
                return;
            }
        }

        filterChain.doFilter(req, res);
    }

    // 인증 처리
    public void setAuthentication(String username) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        Authentication authentication = createAuthentication(username);
        context.setAuthentication(authentication);

        SecurityContextHolder.setContext(context);
        //인증을 처리하는 코드
    }

    // 인증 객체 생성
    private Authentication createAuthentication(String username) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);//username을 통해서 사용자 정보를 가져온다. //UserDetailsServiceImpl에서 구현한 loadUserByUsername() 메소드를 통해서 사용자 정보를 가져온다.
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());//사용자 정보를 통해서 인증 객체를 생성한다. //UsernamePasswordAuthenticationToken을 통해서 인증 객체를 생성한다.
    }

    //인증 객체를 생성하는 코드 //UsernamePasswordAuthenticationToken을 통해서 인증 객체를 생성한다. //사용자 정보를 통해서 인증 객체를 생성한다.

}