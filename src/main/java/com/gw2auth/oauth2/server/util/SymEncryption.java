package com.gw2auth.oauth2.server.util;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class SymEncryption {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 16;

    public static SecretKey generateKey() {
        final KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    public static IvParameterSpec generateIv() {
        final byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static byte[] toBytes(Pair<SecretKey, IvParameterSpec> pair) {
        return toBytes(pair.v1(), pair.v2());
    }

    public static byte[] toBytes(SecretKey key, IvParameterSpec iv) {
        final byte[] keyBytes = key.getEncoded();
        final byte[] ivBytes = iv.getIV();

        return ByteBuffer.allocate(Integer.BYTES + keyBytes.length + Integer.BYTES + ivBytes.length)
                .putInt(keyBytes.length)
                .put(keyBytes)
                .putInt(ivBytes.length)
                .put(ivBytes)
                .array();
    }

    public static Pair<SecretKey, IvParameterSpec> fromBytes(byte[] bytes) {
        final ByteBuffer buf = ByteBuffer.wrap(bytes);

        final int keyLength = buf.getInt();
        final byte[] keyBytes = new byte[keyLength];
        buf.get(keyBytes);

        final int ivLength = buf.getInt();
        final byte[] ivBytes = new byte[ivLength];
        buf.get(ivBytes);

        return new Pair<>(new SecretKeySpec(keyBytes, ALGORITHM), new IvParameterSpec(ivBytes));
    }

    public static OutputStream encrypt(OutputStream out, SecretKey key, IvParameterSpec iv) {
        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }

        return new CipherOutputStream(out, cipher);
    }

    public static InputStream decrypt(InputStream in, SecretKey key, IvParameterSpec iv) {
        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }

        return new CipherInputStream(in, cipher);
    }
}
