package com.gw2auth.oauth2.server.service.gw2.client;

import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;

import java.time.Duration;

public interface Gw2ApiClient extends AutoCloseable {

    ResponseEntity<Resource> get(String path, MultiValueMap<String, String> query, HttpHeaders headers);
    ResponseEntity<Resource> get(Duration timeout, String path, MultiValueMap<String, String> query, HttpHeaders headers);

}
