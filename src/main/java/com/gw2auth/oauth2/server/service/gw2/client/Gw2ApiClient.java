package com.gw2auth.oauth2.server.service.gw2.client;

import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;

import java.time.Duration;

public interface Gw2ApiClient {

    ResponseEntity<Resource> get(String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers);
    ResponseEntity<Resource> get(Duration timeout, String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers);

}
