package com.sparta.board.repository;

import com.sparta.board.entity.Board;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface BoardRepository extends JpaRepository<Board, Long> { //jpa메서드 , Repository가진 이름들은 스프링에서 구현체를 만들어준다.
    List<Board> findAllByOrderByModifiedAtDesc(); //스프링에서 이거에 맞게 가져와준다.
    List<Board> findAllByContentsContainsOrderByModifiedAtDesc(String keyword);//list<board>가 반환타입
}
