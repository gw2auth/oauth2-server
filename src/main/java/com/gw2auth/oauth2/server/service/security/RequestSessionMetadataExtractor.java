package com.gw2auth.oauth2.server.service.security;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Optional;

public interface RequestSessionMetadataExtractor {

    Optional<SessionMetadata> extractMetadataFromRequest(HttpServletRequest request);
}
