package com.gw2auth.oauth2.server.service.account;

import java.time.Instant;
import java.util.Map;

public record AccountLog(Instant timestamp, String message, Map<String, ?> fields) {

}
