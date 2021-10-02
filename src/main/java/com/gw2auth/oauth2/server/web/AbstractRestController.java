package com.gw2auth.oauth2.server.web;

import com.gw2auth.oauth2.server.service.Gw2AuthServiceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;

public abstract class AbstractRestController {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractRestController.class);

    @ExceptionHandler({Gw2AuthServiceException.class})
    public ResponseEntity<ApiErrorResponse> handleException(Gw2AuthServiceException exc) {
        return ResponseEntity
                .status(exc.getProposedStatusCode().orElse(HttpStatus.INTERNAL_SERVER_ERROR))
                .contentType(MediaType.APPLICATION_JSON)
                .body(new ApiErrorResponse(exc.getType(), exc.getLocalizedMessage()));
    }

    @ExceptionHandler({Exception.class})
    public ResponseEntity<ApiErrorResponse> handleGenericException(Exception exc) {
        LOG.error("Unhandled error while processing request", exc);

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.APPLICATION_JSON)
                .body(new ApiErrorResponse(exc.getClass().getSimpleName(), "An unknown error occured while processing your request"));
    }
}
