package com.gw2auth.oauth2.server.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
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

    public static KeyPair loadRsaKeyPair(String _privateKeyPath, String _publicKeyPath) throws IOException, GeneralSecurityException {
        final Path privateKeyPath = Paths.get(_privateKeyPath);
        final Path publicKeyPath = Paths.get(_publicKeyPath);
        try {
            return loadPemRsaKeyPair(privateKeyPath, publicKeyPath);
        } catch (Exception e) {
            return loadPlainRsaKeyPair(privateKeyPath, publicKeyPath);
        }
    }

    private static KeyPair loadPlainRsaKeyPair(Path privateKeyPath, Path publicKeyPath) throws IOException, GeneralSecurityException {
        final KeyFactory kf = KeyFactory.getInstance("RSA");
        final PrivateKey privateKey;
        final PublicKey publicKey;

        KeySpec spec = new PKCS8EncodedKeySpec(Files.readAllBytes(privateKeyPath));
        privateKey = kf.generatePrivate(spec);

        spec = new X509EncodedKeySpec(Files.readAllBytes(publicKeyPath));
        publicKey = kf.generatePublic(spec);

        return new KeyPair(publicKey, privateKey);
    }

    private static KeyPair loadPemRsaKeyPair(Path privateKeyPath, Path publicKeyPath) throws IOException, GeneralSecurityException {
        final KeyFactory kf = KeyFactory.getInstance("RSA");
        final PrivateKey privateKey;
        final PublicKey publicKey;

        try (Reader reader = Files.newBufferedReader(privateKeyPath, StandardCharsets.UTF_8)) {
            try (PemReader pemReader = new PemReader(reader)) {
                final PemObject pemObject = pemReader.readPemObject();
                if (!pemObject.getType().equals("PKCS#8")) {
                    throw new IllegalStateException("private key must be PKCS#8");
                }

                final KeySpec spec = new PKCS8EncodedKeySpec(pemObject.getContent());
                privateKey = kf.generatePrivate(spec);
            }
        }

        try (Reader reader = Files.newBufferedReader(publicKeyPath, StandardCharsets.UTF_8)) {
            try (PemReader pemReader = new PemReader(reader)) {
                final PemObject pemObject = pemReader.readPemObject();
                if (!pemObject.getType().equals("X.509")) {
                    throw new IllegalStateException("public key must be X.509");
                }

                final KeySpec spec = new X509EncodedKeySpec(pemObject.getContent());
                publicKey = kf.generatePublic(spec);
            }
        }

        return new KeyPair(publicKey, privateKey);
    }

    public static KeyPair generateRsaKeyPair() throws GeneralSecurityException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        return keyPairGenerator.generateKeyPair();
    }

    public static void writeKeyPair(KeyPair keyPair, Path privateKeyPath, Path publicKeyPath) throws Exception {
        try (Writer writer = Files.newBufferedWriter(privateKeyPath, StandardCharsets.UTF_8, StandardOpenOption.CREATE)) {
            try (PemWriter pemWriter = new PemWriter(writer)) {
                pemWriter.writeObject(new PemObject(keyPair.getPrivate().getFormat(), keyPair.getPrivate().getEncoded()));
            }
        }

        try (Writer writer = Files.newBufferedWriter(publicKeyPath, StandardCharsets.UTF_8, StandardOpenOption.CREATE)) {
            try (PemWriter pemWriter = new PemWriter(writer)) {
                pemWriter.writeObject(new PemObject(keyPair.getPublic().getFormat(), keyPair.getPublic().getEncoded()));
            }
        }
    }
}
