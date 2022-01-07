package com.gw2auth.oauth2.server.service.gw2;

import com.fasterxml.jackson.core.type.TypeReference;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.gw2.client.Gw2ApiClient;
import com.nimbusds.jose.Header;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class Gw2ApiServiceImpl implements Gw2ApiService {

    private static final Logger LOG = LoggerFactory.getLogger(Gw2ApiServiceImpl.class);
    private static final Pattern ROOT_TOKEN_PATTERN = Pattern.compile("^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{20}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$");

    private final Gw2ApiClient gw2ApiClient;

    @Autowired
    public Gw2ApiServiceImpl(Gw2ApiClient gw2ApiClient) {
        this.gw2ApiClient = gw2ApiClient;
    }

    @Override
    public Gw2TokenInfo getTokenInfo(String gw2ApiToken) {
        return getFromAPI("/v2/tokeninfo", gw2ApiToken, new TypeReference<Gw2TokenInfo>() {});
    }

    @Override
    public Gw2Account getAccount(String gw2ApiToken) {
        return getFromAPI("/v2/account", gw2ApiToken, new TypeReference<Gw2Account>() {});
    }

    @Override
    public Gw2SubToken createSubToken(String token, Set<Gw2ApiPermission> permissions, Instant expirationTime) {
        final MultiValueMap<String, String> query = new LinkedMultiValueMap<>();
        query.add("permissions", permissions.stream().map(Gw2ApiPermission::gw2).collect(Collectors.joining(",")));
        query.add("expire", expirationTime.toString()); // ISO-8601

        final String jwtString = getFromAPI("/v2/createsubtoken", query, token, new TypeReference<GW2CreateSubToken>() {}).subtoken();
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

    private <T> T getFromAPI(String url, String token, TypeReference<T> typeReference) {
        return getFromAPI(url, HttpHeaders.EMPTY, token, typeReference);
    }

    private <T> T getFromAPI(String url, MultiValueMap<String, String> query, String token, TypeReference<T> typeReference) {
        if (token != null && !validateToken(token)) {
            throw new Gw2ApiServiceException(Gw2ApiServiceException.INVALID_API_TOKEN, HttpStatus.BAD_REQUEST);
        }

        ResponseEntity<T> response;
        try {
            response = this.gw2ApiClient.get(url, query, buildRequestHeaders(token), typeReference);
        } catch (Exception e) {
            LOG.warn("unexpected exception during GW2-API-Request for url={}", url, e);
            throw new Gw2ApiServiceException(Gw2ApiServiceException.UNEXPECTED_EXCEPTION, HttpStatus.BAD_GATEWAY);
        }

        if (response.getStatusCode().equals(HttpStatus.UNAUTHORIZED)) {
            throw new Gw2ApiServiceException(Gw2ApiServiceException.INVALID_API_TOKEN, HttpStatus.BAD_REQUEST);
        } else if (!response.getStatusCode().is2xxSuccessful() || !response.hasBody()) {
            throw new Gw2ApiServiceException(Gw2ApiServiceException.BAD_RESPONSE, HttpStatus.BAD_GATEWAY);
        }

        return response.getBody();
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
