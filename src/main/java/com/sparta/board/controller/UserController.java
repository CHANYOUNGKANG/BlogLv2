package com.sparta.board.controller;

import com.sparta.board.dto.SignupRequestDto;
import com.sparta.board.dto.StatusDto;
import com.sparta.board.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.web.bind.annotation.*;


@Slf4j
@RestController// @Controller 값만 전달해줌
@RequiredArgsConstructor
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    // ////////////////////////////////
    @PostMapping("/auth/signup")// 회원가입
    public StatusDto signup(@RequestBody @Valid SignupRequestDto requestDto) {// @RequestBody : 요청받은 데이터를 객체로 변환 // @Valid : 유효성 검사 //   SignupRequestDto : 회원가입 요청을 받는 객체
        userService.signup(requestDto);// 회원가입 요청을 받는 객체를 회원가입 서비스에 넘겨줌 // 회원가입 서비스에서 회원가입 요청을 받는 객체를 처리 //
        return new StatusDto("저장 성공", 200);//   StatusDto : 상태를 나타내는 객체
    }

    // ////////////////////////////////

    @PostMapping("/auth/login")// 로그인 // 로그인 요청을 받는 객체 // 로그인 요청을 받는 객체를 로그인 서비스에 넘겨줌 // 로그인 서비스에서 로그인 요청을 받는 객체를 처리
    public StatusDto login() { // 로그인 요청을 받는 객체를 로그인 서비스에 넘겨줌 // 로그인 서비스에서 로그인 요청을 받는 객체를 처리
        return new StatusDto("로그인 성공", 200);//   StatusDto : 상태를 나타내는 객체 , // 200 : 성공 // 400 : 실패 // 500 : 서버 오류 // 404 : 페이지 없음
    }
    //











}
