package com.gw2auth.oauth2.server.web;

import com.gw2auth.oauth2.server.service.security.AuthenticationHelper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthInfoController extends AbstractRestController {

    @RequestMapping(value = "/api/authinfo", method = RequestMethod.HEAD)
    public ResponseEntity<Void> authinfo() {
        if (AuthenticationHelper.getUser().isPresent()) {
            return ResponseEntity.status(HttpStatus.ACCEPTED).build();
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
