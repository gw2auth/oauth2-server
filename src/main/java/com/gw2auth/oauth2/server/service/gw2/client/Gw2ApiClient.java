package com.gw2auth.oauth2.server.service.gw2.client;

import com.fasterxml.jackson.core.type.TypeReference;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;

import java.util.Optional;

public interface Gw2ApiClient {

    <T> ResponseEntity<T> get(String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers, TypeReference<T> typeReference);

    record Request<T>(String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers, TypeReference<T> typeReference) {

    }

    interface Response<T> {

        boolean isSuccess();
        Optional<ResponseEntity<T>> response();
        Optional<Exception> exception();
    }

    record SuccessResponse<T>(ResponseEntity<T> _response) implements Response<T> {

        @Override
        public boolean isSuccess() {
            return true;
        }

        @Override
        public Optional<ResponseEntity<T>> response() {
            return Optional.of(this._response);
        }

        @Override
        public Optional<Exception> exception() {
            return Optional.empty();
        }
    }

    record FailureResponse<T>(Exception e) implements Response<T> {

        @Override
        public boolean isSuccess() {
            return false;
        }

        @Override
        public Optional<ResponseEntity<T>> response() {
            return Optional.empty();
        }

        @Override
        public Optional<Exception> exception() {
            return Optional.of(this.e);
        }
    }
}
