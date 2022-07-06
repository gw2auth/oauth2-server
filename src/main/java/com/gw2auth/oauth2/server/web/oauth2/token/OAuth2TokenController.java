package com.gw2auth.oauth2.server.web.oauth2.token;

import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import com.gw2auth.oauth2.server.web.AbstractRestController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.util.Set;

@RestController
public class OAuth2TokenController extends AbstractRestController {

    private static final Set<String> FILTER_HEADER_NAMES = Set.of("set-cookie", "transfer-encoding", "keep-alive");

    private final RestTemplate restTemplate;

    @Autowired
    public OAuth2TokenController(@Qualifier("self-proxy-rest-template") RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    // this proxy is required for the Test-UI because on a direct request the server un-authenticates the session
    @PostMapping("/api/oauth2/token")
    public void oauth2Token(@AuthenticationPrincipal Gw2AuthUserV2 user, HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (user == null) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.flushBuffer();
            return;
        }

        final String query = request.getQueryString();
        final StringBuilder url = new StringBuilder("/oauth2/token");

        if (query != null) {
            url.append('?');
            url.append(query);
        }

        this.restTemplate.execute(url.toString(), HttpMethod.POST, (value) -> {}, resp -> {
            response.setStatus(resp.getRawStatusCode());

            resp.getHeaders().forEach((header, values) -> {
                if (!FILTER_HEADER_NAMES.contains(header.toLowerCase())) {
                    for (String value : values) {
                        response.addHeader(header, value);
                    }
                }
            });

            try (InputStream in = resp.getBody()) {
                in.transferTo(response.getOutputStream());
            }

            response.flushBuffer();

            return null;
        });
    }
}
