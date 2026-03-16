package com.example.jwt.controller;

import com.example.jwt.domain.user.dto.UserRequestDto;
import com.example.jwt.domain.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JoinController {

    private final UserService userService;

    @PostMapping("/join")
    public String joinProcess(UserRequestDto userRequestDto) {

        userService.joinProcess(userRequestDto);

        return "success";
    }
}
