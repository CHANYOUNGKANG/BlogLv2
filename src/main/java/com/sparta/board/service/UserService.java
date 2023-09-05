package com.sparta.board.service;

import com.sparta.board.dto.LoginRequestDto;
import com.sparta.board.dto.SignupRequestDto;
import com.sparta.board.entity.User;
import com.sparta.board.repository.UserRepository;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // ADMIN_TOKEN
    private final String ADMIN_TOKEN = "AAABnvxRVklrnYxKZ0aHgTBcXukeZygoC";

    public void signup(SignupRequestDto requestDto) {
        String username = requestDto.getUsername();
        String password = passwordEncoder.encode(requestDto.getPassword());
        System.out.println("password = " + password + "username = " + username);
        // 회원 중복 확인
        Optional<User> checkUsername = userRepository.findByUsername(username);//이름으로 찾아서
        if (checkUsername.isPresent()) {
            throw new IllegalArgumentException("중복된 사용자가 존재합니다.");
        }

        // 사용자 등록
        User user = new User(username, password);
        userRepository.save(user);
    }


    public String login(LoginRequestDto requestDto) {
        String username = requestDto.getUsername();
        String password = requestDto.getPassword();
        System.out.println("password = " + password + "username = " + username);
        // 회원 찾기
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("가입되지 않은 사용자입니다."));//이름으로 찾아서 없으면 예외처리

        // 패스워드 일치 확인
        if (!passwordEncoder.matches(password, user.getPassword())) {//패스워드가 일치하지 않으면 예외처리
            throw new IllegalArgumentException("잘못된 비밀번호입니다.");
        }

        return "로그인 성공";
    }
}