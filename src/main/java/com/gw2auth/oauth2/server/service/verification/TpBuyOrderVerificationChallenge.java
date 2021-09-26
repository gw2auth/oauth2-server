package com.gw2auth.oauth2.server.service.verification;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.gw2.Gw2ApiService;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

@Component
public class TpBuyOrderVerificationChallenge implements VerificationChallenge<TpBuyOrderVerificationChallenge.State> {

    private static final long ID = 2;
    private static final Set<Gw2ApiPermission> REQUIRED_GW2_API_PERMISSIONS = Collections.unmodifiableSet(EnumSet.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.TRADINGPOST));
    private static final Duration TIMEOUT = Duration.ofMinutes(15L);
    private static final long PRICE_RANGE_START = coins(1, 15, 0);
    private static final long PRICE_RANGE_END = coins(30, 0, 0);
    private static final List<Integer> ITEM_IDS = List.of(
            30689,// eternity
            30704,// twilight
            30703,// sunrise
            30699// zap
    );

    private final Gw2ApiService gw2ApiService;

    public TpBuyOrderVerificationChallenge(Gw2ApiService gw2ApiService) {
        this.gw2ApiService = gw2ApiService;
    }

    @Override
    public long getId() {
        return ID;
    }

    @Override
    public Set<Gw2ApiPermission> getRequiredGw2ApiPermissions() {
        return REQUIRED_GW2_API_PERMISSIONS;
    }

    @Override
    public Duration getTimeout() {
        return TIMEOUT;
    }

    @Override
    public Map<String, Object> buildMessage(State state, Locale locale) {
        return Map.of(
                "gw2ItemId", state.itemId(),
                "buyOrderCoins", state.price()
        );
    }

    @Override
    public State start() {
        final ThreadLocalRandom random = ThreadLocalRandom.current();

        final int itemId = ITEM_IDS.get(random.nextInt(0, ITEM_IDS.size()));
        final long price = random.nextLong(PRICE_RANGE_START, PRICE_RANGE_END);

        return new State(itemId, price);
    }

    @Override
    public boolean verify(State state, String gw2ApiToken) {
        return this.gw2ApiService.getCurrentBuyTransactions(gw2ApiToken).stream()
                .filter((transaction) -> transaction.itemId() == state.itemId())
                .anyMatch((transaction) -> transaction.price() == state.price());
    }

    private static long gold(long coins) {
        return coins / 10000L;
    }

    private static long silver(long coins) {
        return (coins / 100L) % 100L;
    }

    private static long copper(long coins) {
        return coins % 100L;
    }

    private static long coins(int gold, int silver, int copper) {
        long coins = copper;
        coins += silver * 100L;
        coins += gold * 10000L;

        return coins;
    }

    public record State(@JsonProperty("itemId") int itemId, @JsonProperty("price") long price) {}
}
