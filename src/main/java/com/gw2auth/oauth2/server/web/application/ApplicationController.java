package com.gw2auth.oauth2.server.web.application;

import com.gw2auth.oauth2.server.service.summary.SummaryService;
import com.gw2auth.oauth2.server.web.AbstractRestController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApplicationController extends AbstractRestController {

    private final SummaryService summaryService;

    @Autowired
    public ApplicationController(SummaryService summaryService) {
        this.summaryService = summaryService;
    }

    @GetMapping(value = "/api/application/summary", produces = MediaType.APPLICATION_JSON_VALUE)
    public ApplicationSummaryResponse getApplicationSummary() {
        return ApplicationSummaryResponse.create(this.summaryService.getApplicationSummary());
    }
}
