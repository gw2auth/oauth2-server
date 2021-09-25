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
    private static final String NAME = "TP Buy-Order";
    private static final String DESCRIPTION = """
            <p class="mb-1">This verification method works by putting a low priced (below 30 Gold) buy-order for very expensive item (for example, Legendaries) in the Trading-Post</p>
            <p class="mb-1">The verification process for this method takes about 15 minutes for finish.</p>
            <p class="mb-0">After the verification process finished, you can remove the buy-order and will receive your placed gold back.</p>
            """;
    private static final String MESSAGE = """
            <p class="mb-1">Use the ingame Trading-Post to place a <strong>buy-order</strong> for the following item and price:</p>
            <p class="mb-0"><strong>%s</strong> at <strong>%d Gold</strong>, <strong>%d Silver</strong>, <strong>%d Copper</strong></p>
            """;
    private static final Set<Gw2ApiPermission> REQUIRED_GW2_API_PERMISSIONS = Collections.unmodifiableSet(EnumSet.of(Gw2ApiPermission.TRADINGPOST));
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
    public String getName() {
        return NAME;
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
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
    public String buildMessage(State state, Locale locale) {
        final String itemName = this.gw2ApiService.getItem(state.itemId()).name();
        final long coins = state.price();

        return String.format(MESSAGE, itemName, gold(coins), silver(coins), copper(coins));
    }

    @Override
    public State start() {
        final ThreadLocalRandom random = ThreadLocalRandom.current();

        final int itemId = ITEM_IDS.get(random.nextInt(random.nextInt(0, ITEM_IDS.size())));
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
