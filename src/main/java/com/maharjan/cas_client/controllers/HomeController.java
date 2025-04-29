package com.maharjan.cas_client.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.security.Principal;

@RestController
public class HomeController {

    @Autowired
    private ServletWebServerApplicationContext webServerAppCtxt;

    @GetMapping("/")
    public String home(Principal principal) {
        int port = webServerAppCtxt.getWebServer().getPort();
        return "Welcome, " + principal.getName() + "! (Running on port: " + port + ")";
    }
}