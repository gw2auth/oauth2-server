package com.gw2auth.oauth2.server.service.summary;

public record ClientSummary(long accounts, long gw2Accounts, long authPast1d, long authPast3d, long authPast7d, long authPast30d) {
}
