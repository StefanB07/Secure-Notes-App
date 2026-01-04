package com.example.secure_notes.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import java.security.Principal;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home(Model model, Principal principal) {
        // Dacă ești logat, 'principal' nu e null
        if (principal != null) {
            // Trimitem numele utilizatorului către HTML ca să-l salutăm
            model.addAttribute("username", principal.getName());
        }
        // Returnează numele fișierului HTML (fără extensia .html)
        return "home";
    }
}