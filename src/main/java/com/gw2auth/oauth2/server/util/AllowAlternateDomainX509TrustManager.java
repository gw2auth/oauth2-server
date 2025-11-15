package com.gw2auth.oauth2.server.util;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;

public class AllowAlternateDomainX509TrustManager extends X509ExtendedTrustManager {

    private static final X509TrustManager DEFAULT_X509_TRUST_MANAGER;
    static {
        final TrustManagerFactory tmf;
        try {
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new IllegalStateException(e);
        }

        DEFAULT_X509_TRUST_MANAGER = Arrays.stream(tmf.getTrustManagers())
                .filter(X509TrustManager.class::isInstance)
                .map(X509TrustManager.class::cast)
                .findFirst()
                .orElseThrow();
    }

    private final X509TrustManager delegate;
    private final String alternateDomain;

    public AllowAlternateDomainX509TrustManager(X509TrustManager delegate, String alternateDomain) {
        this.delegate = Objects.requireNonNull(delegate);
        this.alternateDomain = Objects.requireNonNull(alternateDomain);
    }

    public AllowAlternateDomainX509TrustManager(String alternateDomain) {
        this(DEFAULT_X509_TRUST_MANAGER, alternateDomain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        throw new CertificateException();
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        throw new CertificateException();
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        throw new CertificateException();
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        throw new CertificateException();
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        throw new CertificateException();
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        if (!engine.getPeerHost().equals(this.alternateDomain)) {
            throw new CertificateException("invalid peer host: " + engine.getPeerHost());
        }

        this.delegate.checkServerTrusted(chain, authType);
    }
}
