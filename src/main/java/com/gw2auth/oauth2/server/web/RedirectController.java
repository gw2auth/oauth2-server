package com.gw2auth.oauth2.server.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
public class RedirectController extends AbstractRestController {

    @GetMapping("/faq")
    public ResponseEntity<Void> faq() {
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create("https://github.com/gw2auth/oauth2-server/wiki/FAQ"))
                .build();
    }
}
