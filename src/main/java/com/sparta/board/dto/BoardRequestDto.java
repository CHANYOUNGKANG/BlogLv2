package com.sparta.board.dto;

import lombok.Getter;

@Getter
public class BoardRequestDto {
    private String contents;
    private String title;
//우리한테 데이터를 줄 때 이 정보를 담긴거를 줘 -> 없으면 우린 안됨
}