package com.gw2auth.oauth2.server.service.security;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class RequestSessionMetadataExtractorImpl implements RequestSessionMetadataExtractor {

    private static final Logger LOG = LoggerFactory.getLogger(RequestSessionMetadataExtractorImpl.class);

    @Override
    public Optional<SessionMetadata> extractMetadataFromRequest(HttpServletRequest request) {
        final String latitudeRaw = request.getHeader("Cloudfront-Viewer-Latitude");
        final String longitudeRaw = request.getHeader("Cloudfront-Viewer-Longitude");

        if (latitudeRaw == null || longitudeRaw == null) {
            LOG.warn("CF headers not present: lat={} long={}", latitudeRaw != null, longitudeRaw != null);
            return Optional.of(SessionMetadata.FALLBACK);
        }

        final double latitude;
        final double longitude;

        try {
            latitude = Double.parseDouble(latitudeRaw);
            longitude = Double.parseDouble(longitudeRaw);
        } catch (NumberFormatException e) {
            return Optional.empty();
        }

        return Optional.of(new SessionMetadata(latitude, longitude));
    }
}
