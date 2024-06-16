package com.gw2auth.oauth2.server.service.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.util.SymEncryption;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.time.Duration;

@Service
public class SessionMetadataService {

    private final ObjectMapper mapper;

    @Autowired
    public SessionMetadataService(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public byte[] encryptMetadata(SecretKey key, IvParameterSpec iv, SessionMetadata sessionMetadata) {
        final byte[] metadataBytes;

        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            try (OutputStream out = SymEncryption.encrypt(bos, key, iv)) {
                this.mapper.writeValue(out, sessionMetadata);
            }

            metadataBytes = bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return metadataBytes;
    }

    public SessionMetadata decryptMetadata(SecretKey key, IvParameterSpec iv, byte[] metadata) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(metadata)) {
            try (InputStream in = SymEncryption.decrypt(bis, key, iv)) {
                return this.mapper.readValue(in, SessionMetadata.class);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean isMetadataPlausible(SessionMetadata originalMetadata, SessionMetadata currentMetadata, Duration timePassed) {
        if (originalMetadata.equals(SessionMetadata.FALLBACK)) {
            return true;
        }

        final double distanceTravelledMeters = distance(
                originalMetadata.latitude(),
                currentMetadata.latitude(),
                originalMetadata.longitude(),
                currentMetadata.longitude()
        );

        if (distanceTravelledMeters > 1_000_000.0) {
            // never allow to travel more than 1000km
            return false;
        } else if (distanceTravelledMeters <= 30_000.0) {
            // always allow to travel 30km
            return true;
        }

        // for everything 30km < travel <= 1000km, allow 333km per day
        return distanceTravelledMeters <= 333_333.3 * ((double) timePassed.toSeconds() / 86400.0);
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
