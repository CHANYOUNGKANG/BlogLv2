package com.sparta.board.service;

import com.sparta.board.dto.BoardRequestDto;
import com.sparta.board.dto.BoardResponseDto;
import com.sparta.board.entity.Board;
import com.sparta.board.repository.BoardRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class BoardService {

    private final BoardRepository boardRepository;//

    public BoardService(BoardRepository boardRepository) {
        this.boardRepository = boardRepository;
    }

    public BoardResponseDto createBoard(BoardRequestDto requestDto) {
        // RequestDto -> Entity
        Board board = new Board(requestDto);

        // DB 저장
        Board saveBoard = boardRepository.save(board);

        // Entity -> ResponseDto
        BoardResponseDto boardResponseDto = new BoardResponseDto(saveBoard);

        return boardResponseDto;
    }

    public List<BoardResponseDto> getBoards() {
        // DB 조회
        return boardRepository.findAllByOrderByModifiedAtDesc().stream().map(BoardResponseDto::new).toList();
    }

    public List<BoardResponseDto> getBoardsByKeyword(String keyword) {
        return boardRepository.findAllByContentsContainsOrderByModifiedAtDesc(keyword).stream().map(BoardResponseDto::new).toList();
    }
    @Transactional //변경감지
    public BoardResponseDto updateBoard(Long id, BoardRequestDto requestDto) {
        // 해당 메모가 DB에 존재하는지 확인
        Board board = findBoard(id); // 이친구한테 뺏어온다.
        requestDto.getPassword(); //유저가 입력한 패스워드
        board.getPassword(); // 디비에서 가져온 패스워드
        if(requestDto.getPassword().equals(board.getPassword())){

            board.update(requestDto);
            return new BoardResponseDto(board); //원하는값이 나와야하니까 리턴은 전체를 뱉게 바꿔주기 때문에 BoardResponseDto
            }else {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다."); //throw가 리턴 역할을 해줌

        }

        // board 내용 수정


    }

    public BoardResponseDto deleteBoard(Long id , BoardRequestDto requestDto) {
        // 해당 메모가 DB에 존재하는지 확인
        Board board = findBoard(id); // 이친구한테 뺏어온다.
        requestDto.getPassword(); //유저가 입력한 패스워드
        board.getPassword(); // 디비에서 가져온 패스워드
        if(requestDto.getPassword().equals(board.getPassword())){

           boardRepository.delete(board);
            return new BoardResponseDto(board);
        }else {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");

        }
    }


    private Board findBoard(Long id) {
        return boardRepository.findById(id).orElseThrow(() ->
                new IllegalArgumentException("선택한 블로그는 존재하지 않습니다.")
        );
    }
}
