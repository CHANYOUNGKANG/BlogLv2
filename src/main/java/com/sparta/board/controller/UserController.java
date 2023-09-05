package com.sparta.board.controller;

import com.sparta.board.dto.LoginRequestDto;
import com.sparta.board.dto.SignupRequestDto;
import com.sparta.board.dto.StatusDto;
import com.sparta.board.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
    public ResponseEntity<String> signup(@RequestBody @Valid SignupRequestDto requestDto, BindingResult bindingResult) {// @RequestBody : 요청받은 데이터를 객체로 변환 // @Valid : 유효성 검사 //   SignupRequestDto : 회원가입 요청을 받는 객체
        // Validation 예외처리
        List<FieldError> fieldErrors = bindingResult.getFieldErrors();
        if(fieldErrors.size() > 0) {
            for (FieldError fieldError : bindingResult.getFieldErrors()) {
                log.error(fieldError.getField() + " 필드 : " + fieldError.getDefaultMessage());
                return ResponseEntity.badRequest().body("실패했다 이새끼야 착한 내가 이유를 알려주지" + fieldError.getDefaultMessage());
            }
        }
        System.out.println("requestDto = " + requestDto);
        userService.signup(requestDto);// 회원가입 요청을 받는 객체를 회원가입 서비스에 넘겨줌 // 회원가입 서비스에서 회원가입 요청을 받는 객체를 처리 //
        return ResponseEntity.ok().body("상태코드 : " + HttpStatus.OK.value() + ", 메세지 : " + "회원가입 성공");
    }
}
