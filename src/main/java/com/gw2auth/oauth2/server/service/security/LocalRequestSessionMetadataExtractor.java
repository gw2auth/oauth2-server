package com.gw2auth.oauth2.server.service.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
@Profile("local")
public class LocalRequestSessionMetadataExtractor implements RequestSessionMetadataExtractor {
    @Override
    public Optional<SessionMetadata> extractMetadataFromRequest(HttpServletRequest request) {
        return Optional.of(new SessionMetadata("DE", "Berlin", 0.0, 0.0));
    }
}
