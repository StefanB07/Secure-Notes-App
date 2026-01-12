
package com.example.secure_notes.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import java.security.Principal;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home(Model model, Principal principal) {
        // If user is authenticated, expose username to the view
        if (principal != null) {
            model.addAttribute("username", principal.getName());
        }
        return "home";
    }
}
