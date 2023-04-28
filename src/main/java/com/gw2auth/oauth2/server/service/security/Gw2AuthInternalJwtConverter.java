package com.gw2auth.oauth2.server.service.security;

import com.gw2auth.oauth2.server.service.Clocked;
import com.gw2auth.oauth2.server.util.JWKHelper;
import com.nimbusds.jose.JOSEException;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

public class Gw2AuthInternalJwtConverter implements Clocked {

    private static final String ISSUER = "login.gw2auth.com";
    private static final String SESSION_CLAIM = "session";
    private static final String ENCRYPTION_KEY_CLAIM = "k";

    private final JwtTimestampValidator jwtTimestampValidator;
    private final JwtDecoder jwtDecoder;
    private final JwtEncoder jwtEncoder;

    public Gw2AuthInternalJwtConverter(String keyId, RSAPublicKey publicKey, RSAPrivateKey privateKey) throws JOSEException {
        this.jwtTimestampValidator = new JwtTimestampValidator();

        final NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(List.of(this.jwtTimestampValidator, new JwtIssuerValidator(ISSUER))));

        this.jwtDecoder = jwtDecoder;
        this.jwtEncoder = new NimbusJwtEncoder(JWKHelper.jwkSourceForKeyPair(new KeyPair(publicKey, privateKey), keyId));
    }

    @Override
    public void setClock(Clock clock) {
        this.jwtTimestampValidator.setClock(clock);
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

    public byte[] readEncryptionKey(Jwt jwt) {
        if (!jwt.hasClaim(ENCRYPTION_KEY_CLAIM)) {
            throw new IllegalArgumentException("no encryption key claim");
        }

        return Base64.getDecoder().decode(jwt.getClaimAsString(ENCRYPTION_KEY_CLAIM));
    }

    public Jwt writeJWT(String sessionId, byte[] encryptionKey, Instant creationTime, Instant expirationTime) {
        final JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
                .issuedAt(creationTime)
                .notBefore(creationTime)
                .expiresAt(expirationTime)
                .issuer(ISSUER)
                .claim(SESSION_CLAIM, sessionId)
                .claim(ENCRYPTION_KEY_CLAIM, Base64.getEncoder().withoutPadding().encodeToString(encryptionKey));

        return this.jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claimsBuilder.build()));
    }
}
