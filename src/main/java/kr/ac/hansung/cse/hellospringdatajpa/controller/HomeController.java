package kr.ac.hansung.cse.hellospringdatajpa.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping
    public String home(HttpSession session) {
        // 메시지를 표시한 후 세션에서 제거
        if (session.getAttribute("successMessage") != null || session.getAttribute("errorMessage") != null) {
            session.removeAttribute("successMessage");
            session.removeAttribute("errorMessage");
        }
        return "home";
    }

}
