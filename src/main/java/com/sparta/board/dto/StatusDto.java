package com.sparta.board.dto;

public class StatusDto {
    String msg;
    int statusCode;
    public StatusDto(String msg, int statusCode) {//생성자 //실패했을 때 메시지 //성공했을 때 메시지 //실패했을 때 메시지
        this.msg = msg;//실패했을 때 메시지 //성공했을 때 메시지 //실패했을 때 메시지
        this.statusCode = statusCode; // 200, 400, 401, 500 등  HTTP 상태 코드
    }
}
