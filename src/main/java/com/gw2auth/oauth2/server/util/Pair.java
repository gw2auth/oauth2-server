package com.gw2auth.oauth2.server.util;

import java.io.Serializable;

public record Pair<T1, T2>(T1 v1, T2 v2) implements Serializable {

}
