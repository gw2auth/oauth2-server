package com.gw2auth.oauth2.server.web;

import com.gw2auth.oauth2.server.service.security.AuthenticationHelper;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
public class AuthInfoController extends AbstractRestController {

    @RequestMapping(value = "/api/authinfo", method = RequestMethod.HEAD)
    public ResponseEntity<Void> headAuthinfo() {
        if (AuthenticationHelper.getUser().isPresent()) {
            return ResponseEntity.status(HttpStatus.ACCEPTED).build();
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @RequestMapping(value = "/api/authinfo", method = RequestMethod.GET)
    public ResponseEntity<AuthInfoResponse> authinfo() {
        final Optional<Gw2AuthUserV2> optionalUser = AuthenticationHelper.getUser();
        if (optionalUser.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        final Gw2AuthUserV2 user = optionalUser.get();
        return ResponseEntity.ok(
                new AuthInfoResponse(
                        user.getSessionId(),
                        user.getSessionCreationTime().orElseThrow(),
                        user.getIssuer()
                )
        );
    }
}
