package com.sparta.board.entity;


import com.sparta.board.dto.BoardRequestDto;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity // JPA가 관리할 수 있는 Entity 클래스 지정
@Getter
@Setter
@Table(name = "board") // 매핑할 테이블의 이름을 지정
@NoArgsConstructor
public class Board extends Timestamped {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "contents", nullable = false, length = 500)
    private String contents;

    @Column(name = "title", nullable = false, length = 500)
    private String title;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;


    public Board(BoardRequestDto requestDto, User user) {
        this.contents = requestDto.getContents();
        this.title = requestDto.getTitle();
        this.user = user;
    }

    public void update(BoardRequestDto requestDto, User user) {
        this.contents = requestDto.getContents();
        this.title = requestDto.getTitle();
        this.user = user;
    }

}
