package com.gw2auth.oauth2.server.configuration;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public Customizer<OAuth2LoginConfigurer<HttpSecurity>> oauth2LoginCustomizer() {
        return (oauth2) -> oauth2.loginPage("/login");
    }

    @Bean
    public Customizer<CsrfConfigurer<HttpSecurity>> csrfCustomizer() {
        return (csrf) -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/**/*.css", "/**/*.js", "/favicon.ico", "/robots.txt");
    }

    @Bean
    @Order(2)
    public SecurityFilterChain frontendHttpSecurityFilterChain(HttpSecurity http,
                                                               Customizer<OAuth2LoginConfigurer<HttpSecurity>> oauth2LoginCustomizer,
                                                               Customizer<CsrfConfigurer<HttpSecurity>> csrfCustomizer) throws Exception {
        http
                .authorizeRequests((auth) -> auth.antMatchers("/", "/login", "/privacy-policy", "/legal", "/faq", "/assets/**").permitAll().anyRequest().authenticated())
                .csrf(csrfCustomizer)
                .headers((headers) -> {
                    headers
                            .frameOptions().deny()
                            .contentSecurityPolicy((csp) -> csp.policyDirectives(String.join("; ",
                                    "default-src 'self'",
                                    "connect-src 'self' https://api.guildwars2.com",
                                    "script-src 'self' 'unsafe-inline'",
                                    "style-src 'self' 'unsafe-inline'",
                                    "img-src 'self' https://render.guildwars2.com https://wiki.guildwars2.com/images/ data:"
                            )));
                })
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .oauth2Login(oauth2LoginCustomizer)
                .logout((logout) -> logout.logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler()));

        return http.build();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain apiHttpSecurityFilterChain(HttpSecurity http, Customizer<CsrfConfigurer<HttpSecurity>> csrfCustomizer) throws Exception {
        http
                .antMatcher("/api/**")
                .authorizeRequests((auth) -> {
                    auth
                            .antMatchers("/api/authinfo", "/api/application/summary").permitAll()
                            .anyRequest().authenticated();
                })
                .csrf(csrfCustomizer);

        return http.build();
    }

    @Bean
    @ConditionalOnExpression("${management.endpoint.prometheus.enabled:false} && ${management.server.port:${server.port:8080}} != ${server.port:8080}")
    @Order(0)
    public SecurityFilterChain actuatorSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .antMatcher("/actuator/prometheus")
                .authorizeRequests().anyRequest().permitAll();

        return http.build();
    }
}
