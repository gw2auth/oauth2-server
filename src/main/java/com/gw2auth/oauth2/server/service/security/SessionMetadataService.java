package com.gw2auth.oauth2.server.service.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class SessionMetadataService {

    public Optional<SessionMetadata> extractMetadataFromRequest(HttpServletRequest request) {
        String countryCode = request.getHeader("Cloudfront-Viewer-Country");
        String city = request.getHeader("Cloudfront-Viewer-City");
        String latitudeRaw = request.getHeader("Cloudfront-Viewer-Latitude");
        String longitudeRaw = request.getHeader("Cloudfront-Viewer-Longitude");

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

    public Optional<SessionMetadata> extractMetadataFromMap(Map<String, Object> map) {
        final Object countryCodeRaw = map.get("countryCode");
        final Object cityRaw = map.get("city");
        final Object latitudeRaw = map.get("latitude");
        final Object longitudeRaw = map.get("longitude");

        if (countryCodeRaw instanceof String countryCode && cityRaw instanceof String city
                && latitudeRaw instanceof Double latitude && longitudeRaw instanceof Double longitude) {

            return Optional.of(new SessionMetadata(countryCode, city, latitude, longitude));
        } else {
            return Optional.empty();
        }
    }

    public Map<String, Object> convertMetadataToMap(SessionMetadata metadata) {
        final Map<String, Object> map = new HashMap<>();
        map.put("countryCode", metadata.countryCode());
        map.put("city", metadata.city());
        map.put("latitude", metadata.latitude());
        map.put("longitude", metadata.longitude());

        return map;
    }

    public boolean isMetadataPlausible(SessionMetadata originalMetadata, SessionMetadata currentMetadata, Duration timePassed) {
        final double distanceTravelledMeters = distance(
                originalMetadata.latitude(),
                currentMetadata.latitude(),
                originalMetadata.longitude(),
                currentMetadata.longitude()
        );

        if (timePassed.toDays() >= 3L) {
            // within [3..] days, allow a maximum distance of 1000km (1m meters)
            return distanceTravelledMeters <= 1_000_000.0;
        } else {
            // within [0-3) days, allow a maximum distance of 333km per day
            return distanceTravelledMeters <= 333_333.3 * ((double) timePassed.toSeconds() / 86400.0);
        }
    }

    // brought to you by https://stackoverflow.com/questions/3694380/calculating-distance-between-two-points-using-latitude-longitude
    /**
     * Calculate distance between two points in latitude and longitude taking
     * into account height difference. If you are not interested in height
     * difference pass 0.0. Uses Haversine method as its base.
     * lat1, lon1 Start point lat2, lon2 End point
     * @return Distance in Meters
     */
    public static double distance(double lat1, double lat2, double lon1, double lon2) {
        final int R = 6371; // Radius of the earth

        double latDistance = Math.toRadians(lat2 - lat1);
        double lonDistance = Math.toRadians(lon2 - lon1);
        double a = Math.sin(latDistance / 2) * Math.sin(latDistance / 2)
                + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2))
                * Math.sin(lonDistance / 2) * Math.sin(lonDistance / 2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        double distance = R * c * 1000; // convert to meters

        distance = Math.pow(distance, 2);

        return Math.sqrt(distance);
    }
}
