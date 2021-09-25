package com.gw2auth.oauth2.server.web;

import com.gw2auth.oauth2.server.service.Gw2AuthServiceException;
import com.gw2auth.oauth2.server.web.dto.ApiErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;

public abstract class AbstractRestController {

    @ExceptionHandler({Gw2AuthServiceException.class})
    public ResponseEntity<ApiErrorResponse> handleException(Gw2AuthServiceException exc) {
        return ResponseEntity
                .status(exc.getProposedStatusCode().orElse(HttpStatus.INTERNAL_SERVER_ERROR))
                .contentType(MediaType.APPLICATION_JSON)
                .body(new ApiErrorResponse(exc.getType(), exc.getLocalizedMessage()));
    }

    @ExceptionHandler({Exception.class})
    public ResponseEntity<ApiErrorResponse> handleGenericException(Exception exc) {
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.APPLICATION_JSON)
                .body(new ApiErrorResponse(exc.getClass().getSimpleName(), exc.getLocalizedMessage()));
    }

}
