package com.gw2auth.oauth2.server.service.gw2.client;

import com.fasterxml.jackson.core.type.TypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class ChainedGw2ApiClient implements Gw2ApiClient {

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
        final Iterator<ClientAndMetadata> it = this.chain.iterator();
        ClientAndMetadata clientAndMetadata;
        ResponseEntity<T> response = null;

        while (response == null && it.hasNext()) {
            clientAndMetadata = it.next();

            if (Instant.now().isAfter(clientAndMetadata.cooldownUntil)) {
                response = clientAndMetadata.client.get(path, query, headers, typeReference);

                if (response.getStatusCode() == HttpStatus.TOO_MANY_REQUESTS) {
                    clientAndMetadata.cooldownUntil = Instant.now().plus(this.cooldownDuration);
                    response = null;
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
