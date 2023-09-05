package com.sparta.board.jwt;

import com.sparta.board.entity.UserRoleEnum;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;


import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtil {


    // Header KEY 값
    public static final String AUTHORIZATION_HEADER = "Authorization"; //Cookie의 Name 값이라고 생각
    // 사용자 권한 값의 KEY
    //권한을 가져오기 위한 KEY값이라 생각하면 된다.
    public static final String AUTHORIZATION_KEY = "auth";// 토큰의 데이터를 넣을때 사용자마다 권한이 다르기에 정보를 넣어서 담는다.
    // Token 식별자
    public static final String BEARER_PREFIX = "Bearer ";//Token 앞에다 넣을 용어 -> 규칙 같은 거임
    // 토큰 만료시간
    private final long TOKEN_TIME = 60 * 60 * 24 * 1000L; // 24시간

    @Value("${jwt.secret.key}") // Base64 Encode 한 SecretKey --> application.properties에서 가져온다.
    private String secretKey;
    private Key key;
    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;//알고리즘을 HS256을 선택했다.

    // 로그 설정
    public static final Logger logger = LoggerFactory.getLogger("JWT 관련 로그");
    //APP이 동작하는동안 상태를 시간 순으로 기록하는걸 로그라고 한다.

    @PostConstruct//딱 한번만 받아오는 값을 받아올때마다 요청을 새로 방지하는것
    //
    public void init() {
        byte[] bytes = Base64.getDecoder().decode(secretKey); //Base64로 디코딩해줌
        key = Keys.hmacShaKeyFor(bytes);
    }

    // 토큰 생성
    //JWT 생성
    public String createToken(String username, UserRoleEnum role) {
        Date date = new Date();

        return BEARER_PREFIX +
                Jwts.builder()
                        .setSubject(username) // 사용자 식별자값(ID) ->여기선 username으로 넣음
                        .claim(AUTHORIZATION_KEY, role) // 사용자 권한 key, value -> k값은 claim에서 꺼내쓴다.
                        .setExpiration(new Date(date.getTime() + TOKEN_TIME)) // 만료 시간 -> 현재시간 + 만료시간으로 가져옴
                        .setIssuedAt(date) // 발급일
                        .signWith(key, signatureAlgorithm) // 암호화 알고리즘(HS256) + key를 넣어줌
                        //SECRET KEY와 알고리즘으로 인해 위에 4줄안에 들어간 데이터와 함께 암호화가 된다. + TOKEN으로 만들어진다.
                        // + BEARER_PREFI와 합쳐지면서 반환이 되는 메서드이다.
                        .compact();
    }

    // JWT Cookie 에 저장
    public void addJwtToCookie(String token, HttpServletResponse res) {
        try {
            token = URLEncoder.encode(token, "utf-8").replaceAll("\\+", "%20"); // Cookie Value 에는 공백이 불가능해서 encoding 진행

            Cookie cookie = new Cookie(AUTHORIZATION_HEADER, token); // Name-Value
            cookie.setPath("/");

            // Response 객체에 Cookie 추가
            res.addCookie(cookie);
        } catch (UnsupportedEncodingException e) {
            logger.error(e.getMessage());
        }
    }

    // JWT 토큰 substring
    //앞에 Bearer을 넣기에..
    public String substringToken(String tokenValue) {
        if (StringUtils.hasText(tokenValue) && tokenValue.startsWith(BEARER_PREFIX)) {
            return tokenValue.substring(7);
        }
        logger.error("Not Found Token");
        throw new NullPointerException("Not Found Token");
    }

    // 토큰 검증
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException | SignatureException e) {
            logger.error("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.");
        } catch (ExpiredJwtException e) {
            logger.error("Expired JWT token, 만료된 JWT token 입니다.");
        } catch (UnsupportedJwtException e) {
            logger.error("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.");
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims is empty, 잘못된 JWT 토큰 입니다.");
        }
        return false;
    }

    // 토큰에서 사용자 정보 가져오기
    public Claims getUserInfoFromToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }
    // HttpServletRequest 에서 Cookie Value : JWT 가져오기
    public String getTokenFromRequest(HttpServletRequest req) {
        Cookie[] cookies = req.getCookies();
        if(cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(AUTHORIZATION_HEADER)) {
                    try {
                        return URLDecoder.decode(cookie.getValue(), "UTF-8"); // Encode 되어 넘어간 Value 다시 Decode
                    } catch (UnsupportedEncodingException e) {
                        return null;
                    }
                }
            }
        }
        return null;
    }
    //## 1. JWT 생성
//
//## 2. 생성된 JWT를 쿠키에 저장
//
//## 3. 쿠키에 들어있던 JWT 토큰을 SubString
//
//## 4. JWT 검증
//
//## 5. JWT 에서 사용자 정보 가져오기
}