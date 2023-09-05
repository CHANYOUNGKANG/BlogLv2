package com.sparta.board.controller;

import com.sparta.board.dto.LoginRequestDto;
import com.sparta.board.dto.SignupRequestDto;
import com.sparta.board.dto.StatusDto;
import com.sparta.board.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;

import java.util.List;


@Slf4j
@RestController// @Controller 값만 전달해줌
@RequiredArgsConstructor
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    // ////////////////////////////////
    @PostMapping("/auth/signup")// 회원가입
    public StatusDto signup(@RequestBody @Valid SignupRequestDto requestDto, BindingResult bindingResult) {// @RequestBody : 요청받은 데이터를 객체로 변환 // @Valid : 유효성 검사 //   SignupRequestDto : 회원가입 요청을 받는 객체
        // Validation 예외처리
        List<FieldError> fieldErrors = bindingResult.getFieldErrors();
        if(fieldErrors.size() > 0) {
            for (FieldError fieldError : bindingResult.getFieldErrors()) {
                log.error(fieldError.getField() + " 필드 : " + fieldError.getDefaultMessage());
            }
        }
        System.out.println("requestDto = " + requestDto);
        userService.signup(requestDto);// 회원가입 요청을 받는 객체를 회원가입 서비스에 넘겨줌 // 회원가입 서비스에서 회원가입 요청을 받는 객체를 처리 //
        return new StatusDto("저장 성공", 200);//   StatusDto : 상태를 나타내는 객체
    }
    // ////////////////////////////////
    //
    @PostMapping("/auth/login")// 로그인
    public StatusDto login(@RequestBody @Valid LoginRequestDto requestDto, BindingResult bindingResult,
                           HttpServletResponse response) {
        // Validation 예외처리
        List<FieldError> fieldErrors = bindingResult.getFieldErrors();
        if(fieldErrors.size() > 0) {
            for (FieldError fieldError : bindingResult.getFieldErrors()) {
                log.error(fieldError.getField() + " 필드 : " + fieldError.getDefaultMessage());
            }
            return new StatusDto("입력값이 올바르지 않습니다.", 400);
        }

        // 로그인 처리
        String jwtToken = userService.login(requestDto);// 로그인 요청을 받는 객체를 로그인 서비스에 넘겨줌 // 로그인 서비스에서 로그인 요청을 받는 객체를 처리 //
        // 로그인 성공 시 쿠키에 JWT 토큰 저장
        response.setHeader("Authorization", "Bearer " + jwtToken); // 헤더에 토큰을 넣어줌

        return new StatusDto("로그인 성공", 200); // 상태를 나타내는 객체
    }
}
