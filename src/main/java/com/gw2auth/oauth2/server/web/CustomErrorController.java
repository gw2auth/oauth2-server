package com.gw2auth.oauth2.server.web;

import com.gw2auth.oauth2.server.util.ComposedMDCCloseable;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.webmvc.autoconfigure.error.AbstractErrorController;
import org.springframework.boot.webmvc.error.ErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;

@RestController
public class CustomErrorController extends AbstractErrorController {

    private static final Logger LOG = LoggerFactory.getLogger(CustomErrorController.class);
    private static final ErrorAttributeOptions ERROR_ATTRIBUTE_OPTIONS = ErrorAttributeOptions.of(ErrorAttributeOptions.Include.values())
            .excluding(ErrorAttributeOptions.Include.STACK_TRACE);

    private final ErrorAttributes errorAttributes;

    @Autowired
    public CustomErrorController(ErrorAttributes errorAttributes) {
        super(errorAttributes);
        this.errorAttributes = errorAttributes;
    }

    @GetMapping("/error-internal")
    public ResponseEntity<?> error(HttpServletRequest request) {
        final Map<String, Object> attributes = getErrorAttributes(request, ERROR_ATTRIBUTE_OPTIONS);

        try {
            logError(request, attributes);
        } catch (Exception e) {
            LOG.error("failed to log error; {}", attributes, e);
        }

        return ResponseEntity.status(HttpStatus.FOUND)
                .location(
                        UriComponentsBuilder
                                .fromUriString(request.getRequestURI())
                                .replacePath("/error")
                                .queryParam("status", attributes.get("status"))
                                .queryParam("error", attributes.get("error"))
                                .queryParam("message", attributes.get("message"))
                                .queryParam("path", attributes.get("path"))
                                .build()
                                .toUri()
                )
                .build();
    }

    private void logError(HttpServletRequest request, Map<String, Object> attributes) {
        final Throwable error = this.errorAttributes.getError(new ServletWebRequest(request));

        try (ComposedMDCCloseable mdc = ComposedMDCCloseable.create(attributes, Object::toString)) {
            if (error != null) {
                LOG.error("Unhandled error while processing request", error);
            } else {
                LOG.warn("Unhandled error while processing request");
            }
        }
    }
}
