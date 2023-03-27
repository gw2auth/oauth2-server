package com.gw2auth.oauth2.server.service.security;

import com.gw2auth.oauth2.server.util.JWKHelper;
import com.nimbusds.jose.JOSEException;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

public class Gw2AuthInternalJwtConverter {

    private static final String ISSUER = "login.gw2auth.com";
    private static final String SESSION_CLAIM = "session";
    private static final String METADATA_CLAIM = "metadata";

    private final JwtDecoder jwtDecoder;
    private final JwtEncoder jwtEncoder;

    public Gw2AuthInternalJwtConverter(String keyId, RSAPublicKey publicKey, RSAPrivateKey privateKey) throws JOSEException {
        final NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
        jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(ISSUER));

        this.jwtDecoder = jwtDecoder;
        this.jwtEncoder = new NimbusJwtEncoder(JWKHelper.jwkSourceForKeyPair(new KeyPair(publicKey, privateKey), keyId));
    }

    public Jwt readJWT(String jwtStr) {
        return this.jwtDecoder.decode(jwtStr);
    }

    public String readSessionId(Jwt jwt) {
        final String sessionId = jwt.getClaimAsString(SESSION_CLAIM);
        if (sessionId == null) {
            throw new IllegalArgumentException("no session claim");
        }

        return sessionId;
    }

    public Optional<Map<String, Object>> readSessionMetadata(Jwt jwt) {
        if (!jwt.hasClaim(METADATA_CLAIM)) {
            return Optional.empty();
        }

        return Optional.of(jwt.getClaimAsMap(METADATA_CLAIM));
    }

    public Jwt writeJWT(String sessionId, Map<String, Object> metadata, Instant creationTime, Instant expirationTime) {
        final JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
                .issuedAt(creationTime)
                .notBefore(creationTime)
                .expiresAt(expirationTime)
                .issuer(ISSUER)
                .claim(SESSION_CLAIM, sessionId);

        if (metadata != null) {
            claimsBuilder.claim(METADATA_CLAIM, metadata);
        }

        return this.jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claimsBuilder.build()));
    }
}
