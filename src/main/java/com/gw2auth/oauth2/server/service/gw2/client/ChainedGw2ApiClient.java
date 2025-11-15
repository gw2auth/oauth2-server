package com.gw2auth.oauth2.server.service.gw2.client;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

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
    public ResponseEntity<Resource> get(String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers) {
        return get(null, path, query, headers);
    }

    @Override
    public ResponseEntity<Resource> get(@Nullable Duration timeout, String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers) {
        final Instant timeoutAt;
        if (timeout == null) {
            timeoutAt = Instant.MAX;
        } else {
            timeoutAt = Instant.now().plus(timeout);
        }

        final Iterator<ClientAndMetadata> it = this.chain.iterator();
        Instant now;
        ClientAndMetadata clientAndMetadata;
        ResponseEntity<Resource> response = null;

        while (response == null && (now = Instant.now()).isBefore(timeoutAt) && it.hasNext()) {
            clientAndMetadata = it.next();

            if (now.isAfter(clientAndMetadata.cooldownUntil)) {
                try {
                    if (timeoutAt == Instant.MAX) {
                        response = clientAndMetadata.client.get(path, query, headers);
                    } else {
                        response = clientAndMetadata.client.get(Duration.between(now, timeoutAt), path, query, headers);
                    }
                } catch (Exception e) {
                    LOG.warn("unexpected exception thrown in gw2 api request chain (client {})", clientAndMetadata.client, e);
                }

                if (response != null) {
                    if (response.getStatusCode() == HttpStatus.REQUEST_TIMEOUT) {
                        response = null;
                    } else if (response.getStatusCode() == HttpStatus.TOO_MANY_REQUESTS) {
                        LOG.info("client {} got a 429; cooling down",  clientAndMetadata.client);

                        clientAndMetadata.cooldownUntil = Instant.now().plus(this.cooldownDuration);
                        response = null;
                    }
                }
            }
        }

        if (response == null) {
            LOG.warn("end of chain reached; all clients are cooling down or timed out");
            response = ResponseEntity.status(HttpStatus.REQUEST_TIMEOUT).body(null);
        }

        return response;
    }

    @Override
    public String toString() {
        return String.format("%s[%s]", getClass().getSimpleName(), this.chain.stream().map(Objects::toString).collect(Collectors.joining(",")));
    }

    @Override
    public void close() throws Exception {
        Exception exc = null;

        for (ClientAndMetadata clientAndMetadata : this.chain) {
            try {
                clientAndMetadata.client.close();
            } catch (Exception e) {
                if (exc == null) {
                    exc = e;
                } else {
                    exc.addSuppressed(e);
                }
            }
        }

        if (exc != null) {
            throw exc;
        }
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
