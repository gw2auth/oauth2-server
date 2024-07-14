package com.gw2auth.oauth2.server.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.servlet.error.AbstractErrorController;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;

@RestController
public class CustomErrorController extends AbstractErrorController {

    @Autowired
    public CustomErrorController(ErrorAttributes errorAttributes) {
        super(errorAttributes);
    }

    @GetMapping("/error")
    public ResponseEntity<?> error(HttpServletRequest request) {
        final Map<String, Object> attributes = getErrorAttributes(request, getErrorAttributeOptions());

        return ResponseEntity.status(HttpStatus.FOUND)
                .location(
                        UriComponentsBuilder
                                .fromUriString(request.getRequestURI())
                                .replacePath("/error")
                                .queryParam("status", attributes.get("status"))
                                .queryParam("error", attributes.get("error"))
                                .queryParam("message", attributes.get("message"))
                                .queryParam("path", attributes.get("path"))
                                .build()
                                .toUri()
                )
                .build();
    }

    protected ErrorAttributeOptions getErrorAttributeOptions() {
        return ErrorAttributeOptions.defaults()
                .including(ErrorAttributeOptions.Include.EXCEPTION)
                .including(ErrorAttributeOptions.Include.MESSAGE)
                .including(ErrorAttributeOptions.Include.PATH);
    }
}
