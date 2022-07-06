package com.gw2auth.oauth2.server.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public final class JWKHelper {

    public static JWKSource<SecurityContext> jwkSourceForKeyPair(KeyPair keyPair, String keyPairId) throws JOSEException {
        RSAKey.Builder builder = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate());

        if (keyPairId != null) {
            builder = builder.keyID(keyPairId);
        } else {
            builder = builder.keyIDFromThumbprint();
        }

        final JWKSet jwkSet = new JWKSet(builder.build());
        return new ImmutableJWKSet<>(jwkSet);
    }

    public static KeyPair loadRsaKeyPair(String privateKeyPath, String publicKeyPath) throws IOException, GeneralSecurityException {
        final KeyFactory kf = KeyFactory.getInstance("RSA");
        final PrivateKey privateKey;
        final PublicKey publicKey;

        KeySpec spec = new PKCS8EncodedKeySpec(Files.readAllBytes(Paths.get(privateKeyPath)));
        privateKey = kf.generatePrivate(spec);

        spec = new X509EncodedKeySpec(Files.readAllBytes(Paths.get(publicKeyPath)));
        publicKey = kf.generatePublic(spec);

        return new KeyPair(publicKey, privateKey);
    }

    public static KeyPair generateRsaKeyPair() throws GeneralSecurityException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        return keyPairGenerator.generateKeyPair();
    }
}
