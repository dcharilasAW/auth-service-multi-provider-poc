package org.example.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GamesController {

    @PreAuthorize("hasAuthority('GAME_VIEW')")
    @GetMapping("/games")
    public String info() {
        SecurityContextHolder.getContext().getAuthentication();
        return "Fantastic games, you click on shiny stuff and win money.";
    }

    @PreAuthorize("hasAuthority('GAME_PLAY')")
    @PostMapping("/games/play")
    public String play() {
        SecurityContextHolder.getContext().getAuthentication();
        return "You have won!";
    }
}
