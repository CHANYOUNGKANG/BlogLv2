package com.sparta.board.dto;


import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignupRequestDto {//회원가입 요청 정보
    @Pattern(regexp = "^[a-z0-9가-힣]{4,10}$", message = "아이디 똑바로 해라 새끼야")//4~10자리의 영문 소문자와 숫자
    private String username;
    @Pattern(regexp = "^[A-Za-z0-9]{8,15}$", message = "비밀번호 틀렸다 새끼야")//8~15자리의 영문 대소문자와 숫자
    private String password;
    private boolean admin = false; // 딱히 요청 없으면 닥치고 넌 일반유저다 이새끼야
    private String adminToken = ""; // 관리자 토큰이 없다 이새끼야
}
