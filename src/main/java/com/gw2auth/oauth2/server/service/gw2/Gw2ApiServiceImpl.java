package com.gw2auth.oauth2.server.service.gw2;

import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class Gw2ApiServiceImpl implements Gw2ApiService {

    private static final Logger LOG = LoggerFactory.getLogger(Gw2ApiServiceImpl.class);

    private final RestTemplate restTemplate;

    @Autowired
    public Gw2ApiServiceImpl(@Qualifier("gw2-rest-template") RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public Gw2TokenInfo getTokenInfo(String gw2ApiToken) {
        return getFromAPI("/v2/tokeninfo", gw2ApiToken, Gw2TokenInfo.class);
    }

    @Override
    public Gw2Account getAccount(String gw2ApiToken) {
        return getFromAPI("/v2/account", gw2ApiToken, Gw2Account.class);
    }

    @Override
    public Gw2SubToken createSubToken(String token, Set<Gw2ApiPermission> permissions, Instant expirationTime) {
        final String jwtString = getFromAPI(
                UriComponentsBuilder.fromPath("/v2/createsubtoken")
                        .queryParam("permissions", permissions.stream().map(Gw2ApiPermission::gw2).collect(Collectors.joining(",")))
                        .queryParam("expire", expirationTime.toString())// ISO-8601
                        .toUriString(),
                token,
                GW2CreateSubToken.class
        ).subtoken();

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
    public Gw2Item getItem(int itemId) {
        return getFromAPI("/v2/items/" + itemId, null, Gw2Item.class);
    }

    @Override
    public List<Gw2Transaction> getCurrentBuyTransactions(String token) {
        return getFromAPI("/v2/commerce/transactions/current/buys", token, new ParameterizedTypeReference<>() {});
    }

    private <T> T getFromAPI(String url, String token, Class<T> clazz) {
        return getFromAPI(url, token, exchangeByClass(clazz));
    }

    private <T> T getFromAPI(String url, String token, ParameterizedTypeReference<T> reference) {
        return getFromAPI(url, token, exchangeByReference(reference));
    }

    private <T> T getFromAPI(String url, String token, Exchanger<T> exchanger) {
        ResponseEntity<T> response;
        try {
            response = exchanger.exchange(this.restTemplate, url, HttpMethod.GET, new HttpEntity<>(buildRequestHeaders(token)));
        } catch (HttpClientErrorException e) {
            response = ResponseEntity.status(e.getStatusCode()).build();
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
        final HttpHeaders headers = new HttpHeaders();

        if (token != null) {
            headers.add("Authorization", "Bearer " + token);
        }

        return headers;
    }

    private record GW2CreateSubToken(@Value("subtoken") String subtoken) { }

    @FunctionalInterface
    private interface Exchanger<T> {

        ResponseEntity<T> exchange(RestTemplate restTemplate, String url, HttpMethod method, HttpEntity<T> entity);
    }

    private static <T> Exchanger<T> exchangeByClass(Class<T> clazz) {
        return (restTemplate, url, method, entity) ->  restTemplate.exchange(url, method, entity, clazz);
    }

    private static <T> Exchanger<T> exchangeByReference(ParameterizedTypeReference<T> reference) {
        return (restTemplate, url, method, entity) ->  restTemplate.exchange(url, method, entity, reference);
    }
}
