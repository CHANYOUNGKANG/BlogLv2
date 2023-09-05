package com.sparta.board.repository;

import com.sparta.board.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;


public interface UserRepository extends JpaRepository<User, Long> { //jpa메서드 , Repository가진 이름들은 스프링에서 구현체를 만들어준다.
    Optional<User> findByUsername(String username);//이름으로 찾기
}