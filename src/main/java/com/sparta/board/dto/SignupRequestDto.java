package com.sparta.board.dto;


import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignupRequestDto {//회원가입 요청 정보
    @Pattern(regexp = "^[a-z0-9]{4,10}$")//4~10자리의 영문 소문자와 숫자
    private String username;
    @Pattern(regexp = "^[A-Za-z0-9]{8,15}$")//8~15자리의 영문 대소문자와 숫자
    private String password;
}
