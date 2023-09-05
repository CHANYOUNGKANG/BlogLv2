package com.sparta.board.controller;


import com.sparta.board.dto.BoardRequestDto;
import com.sparta.board.dto.BoardResponseDto;
import org.springframework.web.bind.annotation.*;

import java.util.List;
//
//@RestController
//@RequestMapping("/api")
//
//public class BoardController {

//    private final BoardService boardService;
//
//    public BoardController(BoardService boardService) {
//        this.boardService = boardService;
//    }
//
//    @PostMapping("/boards")
//    public BoardResponseDto createBoard(@RequestBody BoardRequestDto requestDto) {
//        return boardService.createBoard(requestDto);
//    }
//
//    @GetMapping("/boards")
//    public List<BoardResponseDto> getBoards() {
//
//        return boardService.getBoards();
//    }
//
//    @GetMapping("/boards/contents")
//    public List<BoardResponseDto> getBoardsByKeyword(String keyword){
//        return boardService.getBoardsByKeyword(keyword);
//    }
//
//    @PutMapping("/boards/{id}")
//    public BoardResponseDto updateBoard(@PathVariable Long id, @RequestBody BoardRequestDto requestDto) {
//
//        return boardService.updateBoard(id, requestDto);
//    }
//
//    @DeleteMapping("/boards/{id}")
//    public BoardResponseDto deleteBoard(@PathVariable Long id, @RequestBody BoardRequestDto requestDto) {
//
//        return boardService.deleteBoard(id, requestDto);
//
//    }
//}
