package com.gw2auth.oauth2.server.service.gw2;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.gw2.client.Gw2ApiClient;
import com.gw2auth.oauth2.server.util.FunctionWithExc;
import com.gw2auth.oauth2.server.util.SupplierWithExc;
import com.nimbusds.jose.Header;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class Gw2ApiServiceImpl implements Gw2ApiService {

    private static final Logger LOG = LoggerFactory.getLogger(Gw2ApiServiceImpl.class);
    private static final Pattern ROOT_TOKEN_PATTERN = Pattern.compile("^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{20}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$");
    private static final ThreadLocal<Deque<Long>> TIMEOUT_AT_TL = new ThreadLocal<>();

    private final Gw2ApiClient gw2ApiClient;
    private final ObjectMapper mapper;

    @Autowired
    public Gw2ApiServiceImpl(Gw2ApiClient gw2ApiClient, ObjectMapper mapper) {
        this.gw2ApiClient = gw2ApiClient;
        this.mapper = mapper;
    }

    @Override
    public Gw2TokenInfo getTokenInfo(String gw2ApiToken) {
        return getFromAPI("/v2/tokeninfo", gw2ApiToken,Gw2TokenInfo.class);
    }

    @Override
    public Gw2Account getAccount(String gw2ApiToken) {
        return getFromAPI("/v2/account", gw2ApiToken, Gw2Account.class);
    }

    @Override
    public Gw2SubToken createSubToken(String token, Set<Gw2ApiPermission> permissions, Instant expirationTime) {
        final MultiValueMap<String, String> query = new LinkedMultiValueMap<>();
        query.add("permissions", permissions.stream().map(Gw2ApiPermission::gw2).collect(Collectors.joining(",")));
        query.add("expire", expirationTime.toString()); // ISO-8601

        final String jwtString = getFromAPI("/v2/createsubtoken", query, token, GW2CreateSubToken.class).subtoken();
        final Set<Gw2ApiPermission> gw2ApiPermissions;
        try {
            final JWT jwt = JWTParser.parse(jwtString);
            gw2ApiPermissions = Optional.ofNullable(jwt.getJWTClaimsSet().getStringListClaim("permissions"))
                    .stream()
                    .flatMap(List::stream)
                    .flatMap((permission) -> Gw2ApiPermission.fromGw2(permission).stream())
                    .collect(Collectors.toSet());
        } catch (ParseException e) {
            throw new Gw2ApiServiceException(Gw2ApiServiceException.SUBTOKEN_JWT_PARSING_ERROR);
        }

        return new Gw2SubToken(jwtString, gw2ApiPermissions);
    }

    @Override
    public List<Gw2Transaction> getCurrentBuyTransactions(String token) {
        return getFromAPI("/v2/commerce/transactions/current/buys", token, new TypeReference<List<Gw2Transaction>>() {});
    }

    @Override
    public <T, EXC extends Exception> T withTimeout(Duration timeout, SupplierWithExc<T, EXC> supplierWithExc) throws EXC {
        Deque<Long> timeoutAtStack = TIMEOUT_AT_TL.get();
        if (timeoutAtStack == null) {
            timeoutAtStack = new ArrayDeque<>();
            TIMEOUT_AT_TL.set(timeoutAtStack);
        }

        timeoutAtStack.addLast(System.nanoTime() + timeout.toNanos());
        try {
            return supplierWithExc.get();
        } finally {
            timeoutAtStack.removeLast();
            if (timeoutAtStack.isEmpty()) {
                TIMEOUT_AT_TL.remove();
            }
        }
    }

    private <T> T getFromAPI(String url, String token, TypeReference<T> typeReference) {
        return getFromAPI(url, HttpHeaders.EMPTY, token, typeReference);
    }

    private <T> T getFromAPI(String url, MultiValueMap<String, String> query, String token, TypeReference<T> typeReference) {
        return getFromAPI(url, query, token, (in) -> this.mapper.readValue(in, typeReference));
    }

    private <T> T getFromAPI(String url, String token, Class<T> clazz) {
        return getFromAPI(url, HttpHeaders.EMPTY, token, clazz);
    }

    private <T> T getFromAPI(String url, MultiValueMap<String, String> query, String token, Class<T> clazz) {
        return getFromAPI(url, query, token, (in) -> this.mapper.readValue(in, clazz));
    }

    private <T> T getFromAPI(String url, MultiValueMap<String, String> query, String token, FunctionWithExc<? super InputStream, ? extends T, IOException> function) {
        if (token != null && !validateToken(token)) {
            throw new InvalidApiTokenException();
        }

        query = new LinkedMultiValueMap<>(query);
        query.set(API_VERSION_PARAM, API_VERSION);

        final Long timeoutAt = Optional.ofNullable(TIMEOUT_AT_TL.get()).map(Deque::peekLast).orElse(null);

        ResponseEntity<Resource> response;
        try {
            if (timeoutAt == null) {
                response = this.gw2ApiClient.get(url, query, buildRequestHeaders(token));
            } else {
                response = this.gw2ApiClient.get(Duration.ofNanos(timeoutAt - System.nanoTime()), url, query, buildRequestHeaders(token));
            }
        } catch (Exception e) {
            LOG.warn("unexpected exception during GW2-API-Request for url={}", url, e);
            throw new Gw2ApiServiceException(Gw2ApiServiceException.UNEXPECTED_EXCEPTION, HttpStatus.BAD_GATEWAY);
        }

        final Resource body = response.getBody();

        if (!response.getStatusCode().is2xxSuccessful() || body == null) {
            if (body != null) {
                JsonNode json;

                try (InputStream in = body.getInputStream()) {
                    json = this.mapper.readTree(in);
                } catch (IOException e) {
                    json = null;
                }

                if (json != null && json.has("text") && json.get("text").asText().equals("invalid key")) {
                    throw new InvalidApiTokenException();
                }
            }

            if (response.getStatusCode().equals(HttpStatus.UNAUTHORIZED) || response.getStatusCode().equals(HttpStatus.FORBIDDEN)) {
                throw new InvalidApiTokenException();
            } else {
                throw new Gw2ApiServiceException(Gw2ApiServiceException.BAD_RESPONSE, HttpStatus.BAD_GATEWAY);
            }
        }

        try (InputStream in = body.getInputStream()) {
            return function.apply(in);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static HttpHeaders buildRequestHeaders(String token) {
        if (token == null) {
            return HttpHeaders.EMPTY;
        }

        final HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + token);

        return headers;
    }

    private static boolean validateToken(String token) {
        if (ROOT_TOKEN_PATTERN.matcher(token).matches()) {
            return true;
        } else {
            final Header jwtHeader;
            try {
                jwtHeader = JWTParser.parse(token).getHeader();
            } catch (ParseException e) {
                return false;
            }

            return jwtHeader.getAlgorithm().getName().equals("HS256") && jwtHeader.getType().equals(JOSEObjectType.JWT);
        }
    }

    private record GW2CreateSubToken(@Value("subtoken") String subtoken) { }
}
