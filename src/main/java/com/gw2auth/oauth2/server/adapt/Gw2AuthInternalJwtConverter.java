package com.gw2auth.oauth2.server.adapt;

import com.gw2auth.oauth2.server.util.JWKHelper;
import com.nimbusds.jose.JOSEException;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;

public class Gw2AuthInternalJwtConverter {

    private static final String ISSUER = "login.gw2auth.com";
    private static final String SESSION_CLAIM = "session";
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

    public Jwt writeJWT(String sessionId, Instant creationTime, Instant expirationTime) {
        return this.jwtEncoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).build(),
                JwtClaimsSet.builder()
                        .issuedAt(creationTime)
                        .notBefore(creationTime)
                        .expiresAt(expirationTime)
                        .issuer(ISSUER)
                        .claim(SESSION_CLAIM, sessionId)
                        .build()
        ));
    }
}
