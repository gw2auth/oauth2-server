package com.gw2auth.oauth2.server.service.gw2.client;

import com.fasterxml.jackson.core.type.TypeReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class ChainedGw2ApiClient implements Gw2ApiClient {

    private static final Logger LOG = LoggerFactory.getLogger(ChainedGw2ApiClient.class);

    private final List<ClientAndMetadata> chain;
    private final Duration cooldownDuration;

    public ChainedGw2ApiClient(Collection<Gw2ApiClient> chain, Duration cooldownDuration) {
        if (chain.isEmpty()) {
            throw new IllegalArgumentException();
        }

        this.cooldownDuration = cooldownDuration;

        final List<ClientAndMetadata> tempChain = new ArrayList<>(chain.size());

        for (Gw2ApiClient client : chain) {
            tempChain.add(new ClientAndMetadata(client, Instant.MIN));
        }

        this.chain = List.copyOf(tempChain);
    }

    @Override
    public <T> ResponseEntity<T> get(String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers, TypeReference<T> typeReference) {
        return get(null, path, query, headers, typeReference);
    }

    @Override
    public <T> ResponseEntity<T> get(long timeout, TimeUnit timeUnit, String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers, TypeReference<T> typeReference) {
        return get(Duration.ofNanos(timeUnit.toNanos(timeout)), path, query, headers, typeReference);
    }

    private <T> ResponseEntity<T> get(Duration timeout, String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers, TypeReference<T> typeReference) {
        final Instant timeoutAt;
        if (timeout == null) {
            timeoutAt = Instant.MAX;
        } else {
            timeoutAt = Instant.now().plus(timeout);
        }

        final Iterator<ClientAndMetadata> it = this.chain.iterator();
        Instant now;
        ClientAndMetadata clientAndMetadata;
        ResponseEntity<T> response = null;

        while (response == null && it.hasNext()) {
            now = Instant.now();
            clientAndMetadata = it.next();

            if (now.isAfter(timeoutAt)) {
                response = ResponseEntity.status(HttpStatus.REQUEST_TIMEOUT).body(null);
            } else if (now.isAfter(clientAndMetadata.cooldownUntil)) {
                try {
                    response = clientAndMetadata.client.get(path, query, headers, typeReference);
                } catch (Exception e) {
                    LOG.warn("unexpected exception thrown in gw2 api request chain", e);
                }

                if (response != null) {
                    if (response.getStatusCode() == HttpStatus.TOO_MANY_REQUESTS) {
                        clientAndMetadata.cooldownUntil = Instant.now().plus(this.cooldownDuration);
                        response = null;
                    }
                }
            }
        }

        if (response == null) {
            throw new RuntimeException("end of chain reached; all clients are cooling down");
        }

        return response;
    }

    private static class ClientAndMetadata {

        private final Gw2ApiClient client;
        private volatile Instant cooldownUntil;

        private ClientAndMetadata(Gw2ApiClient client, Instant cooldownUntil) {
            this.client = client;
            this.cooldownUntil = cooldownUntil;
        }
    }
}
