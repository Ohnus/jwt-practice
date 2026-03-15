package com.example.jwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// 스프링 자체에서 페이지를 로딩하는 SSR 방식이 아닌 API 서버로 구성하는 SPA 방식을 감안하고 진행할 예정이다.
// 따라서 페이지가 아닌 응답 바디 데이터를 넘기기 위해 @ResponseBody 어노테이션을 추가하거나 @RestController 어노테이션 하나로 진행한다.
@RestController
public class MainController {

    @GetMapping("/")
    public String MainP() {

        return "Main Controller";
    }
}
