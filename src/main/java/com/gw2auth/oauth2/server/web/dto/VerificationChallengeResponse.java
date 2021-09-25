package com.gw2auth.oauth2.server.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.verification.VerificationChallenge;

import java.util.Set;

public record VerificationChallengeResponse(@JsonProperty("id") long id,
                                            @JsonProperty("name") String name,
                                            @JsonProperty("description") String description,
                                            @JsonProperty("requiredGw2ApiPermissions") Set<Gw2ApiPermission> requiredGw2ApiPermissions) {

    public static VerificationChallengeResponse create(VerificationChallenge<?> value) {
        return new VerificationChallengeResponse(value.getId(), value.getName(), value.getDescription(), value.getRequiredGw2ApiPermissions());
    }
}
