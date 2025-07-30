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
import java.util.List;

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
        return new KeyPair(loadRsaPublicKey(_publicKeyPath), loadRsaPrivateKey(_privateKeyPath));
    }

    public static PrivateKey loadRsaPrivateKey(String _path) throws IOException, GeneralSecurityException {
        final Path path = Paths.get(_path);
        final KeyFactory kf = KeyFactory.getInstance("RSA");
        try {
            return loadPemRsaPrivateKey(kf, path);
        } catch (Exception e) {
            return loadPlainRsaPrivateKey(kf, path);
        }
    }

    private static PrivateKey loadPlainRsaPrivateKey(KeyFactory kf, Path path) throws IOException, GeneralSecurityException {
        final KeySpec spec = new PKCS8EncodedKeySpec(Files.readAllBytes(path));
        return kf.generatePrivate(spec);
    }

    private static PrivateKey loadPemRsaPrivateKey(KeyFactory kf, Path path) throws IOException, GeneralSecurityException {
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            try (PemReader pemReader = new PemReader(reader)) {
                final PemObject pemObject = pemReader.readPemObject();
                if (!pemObject.getType().equals("PKCS#8")) {
                    throw new IllegalStateException("private key must be PKCS#8");
                }

                final KeySpec spec = new PKCS8EncodedKeySpec(pemObject.getContent());
                return kf.generatePrivate(spec);
            }
        }
    }

    public static PublicKey loadRsaPublicKey(String _path) throws IOException, GeneralSecurityException {
        final Path path = Paths.get(_path);
        final KeyFactory kf = KeyFactory.getInstance("RSA");
        try {
            return loadPemRsaPublicKey(kf, path);
        } catch (Exception e) {
            return loadPlainRsaPublicKey(kf, path);
        }
    }

    private static PublicKey loadPlainRsaPublicKey(KeyFactory kf, Path path) throws IOException, GeneralSecurityException {
        final KeySpec spec = new X509EncodedKeySpec(Files.readAllBytes(path));
        return kf.generatePublic(spec);
    }

    private static PublicKey loadPemRsaPublicKey(KeyFactory kf, Path path) throws IOException, GeneralSecurityException {
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            try (PemReader pemReader = new PemReader(reader)) {
                final PemObject pemObject = pemReader.readPemObject();
                if (!pemObject.getType().equals("X.509")) {
                    throw new IllegalStateException("public key must be X.509");
                }

                final KeySpec spec = new X509EncodedKeySpec(pemObject.getContent());
                return kf.generatePublic(spec);
            }
        }
    }

    public static KeyPair generateRsaKeyPair() throws GeneralSecurityException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        return keyPairGenerator.generateKeyPair();
    }

    public static void main(String[] args) throws Exception {
        final String userHome = System.getProperty("user.home");
        if (userHome == null) {
            throw new IllegalStateException("user.home is null");
        }

        final Path gw2authConfigBasePath = Paths.get(userHome).resolve(".gw2auth");
        for (String name : List.of("session_id_rsa_1", "session_id_rsa_2")) {
            final KeyPair keyPair = generateRsaKeyPair();
            writeKeyPair(keyPair, gw2authConfigBasePath.resolve(name), gw2authConfigBasePath.resolve(name + ".pub"));
        }
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
