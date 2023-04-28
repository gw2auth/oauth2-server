package com.gw2auth.oauth2.server.service.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
@Profile("!local")
public class RequestSessionMetadataExtractorImpl implements RequestSessionMetadataExtractor {
    @Override
    public Optional<SessionMetadata> extractMetadataFromRequest(HttpServletRequest request) {
        final String countryCode = request.getHeader("Cloudfront-Viewer-Country");
        final String city = request.getHeader("Cloudfront-Viewer-City");
        final String latitudeRaw = request.getHeader("Cloudfront-Viewer-Latitude");
        final String longitudeRaw = request.getHeader("Cloudfront-Viewer-Longitude");

        if (countryCode == null || city == null || latitudeRaw == null || longitudeRaw == null) {
            return Optional.empty();
        }

        final double latitude;
        final double longitude;

        try {
            latitude = Double.parseDouble(latitudeRaw);
            longitude = Double.parseDouble(longitudeRaw);
        } catch (NumberFormatException e) {
            return Optional.empty();
        }

        return Optional.of(new SessionMetadata(countryCode, city, latitude, longitude));
    }
}
