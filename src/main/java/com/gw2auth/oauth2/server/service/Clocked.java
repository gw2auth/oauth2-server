package com.gw2auth.oauth2.server.service;

import java.time.Clock;

public interface Clocked {

    void setClock(Clock clock);
}
