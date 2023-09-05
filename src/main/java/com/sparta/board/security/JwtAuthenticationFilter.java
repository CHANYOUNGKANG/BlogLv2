package com.sparta.board.security;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.sparta.board.dto.LoginRequestDto;
import com.sparta.board.entity.UserRoleEnum;
import com.sparta.board.jwt.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@Slf4j(topic = "로그인 및 JWT 생성")
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {//UsernamePasswordAuthenticationFilter를 상속받아서 사용한다.
    private final JwtUtil jwtUtil;

    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
        setFilterProcessesUrl("/api/auth/login");//로그인 요청이 들어오면 이 주소로 들어온다. 명세서에서 요청한 url을 확인할 수 있다.
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            LoginRequestDto requestDto = new ObjectMapper().readValue(request.getInputStream(), LoginRequestDto.class);

            return getAuthenticationManager().authenticate(//AuthenticationManager를 통해서 인증을 진행한다. //AuthenticationManager는 AuthenticationProvider를 통해서 인증을 진행한다.
                    new UsernamePasswordAuthenticationToken(//UsernamePasswordAuthenticationToken을 통해서 인증을 진행한다.
                            requestDto.getUsername(),//로그인 요청에서 받은 username과 password를 토큰에 담아서 AuthenticationManager에게 전달한다.
                            requestDto.getPassword(),//로그인 요청에서 받은 username과 password를 토큰에 담아서 AuthenticationManager에게 전달한다.
                            null//로그인 요청에서 받은 username과 password를 토큰에 담아서 AuthenticationManager에게 전달한다.
                    )
            );
        } catch (IOException e) {//예외처리
            log.error(e.getMessage());//에러메시지를 로그로 남긴다.
            throw new RuntimeException(e.getMessage());//예외를 던진다.
        }
    }
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException {
        String username = ((UserDetailsImpl) authResult.getPrincipal()).getUsername();
        UserRoleEnum role = ((UserDetailsImpl) authResult.getPrincipal()).getUser().getRole();

        String token = jwtUtil.createToken(username, role);
        response.addHeader(JwtUtil.AUTHORIZATION_HEADER, token);

        // 로그인 성공 메세지 전달
        response.setContentType("text/plain");
        response.setCharacterEncoding("UTF-8");
        String massage = "로그인 성공";
        response.getWriter().write("상태코드 : " + response.getStatus() + ", 메세지 : " + massage);
    }



    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        log.info("로그인 실패");
        response.setStatus(401);
    }

}
