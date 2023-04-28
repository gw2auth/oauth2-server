package com.gw2auth.oauth2.server.service.application.client.account;

import com.gw2auth.oauth2.server.repository.application.account.ApplicationAccountRepository;
import com.gw2auth.oauth2.server.repository.application.account.ApplicationAccountSubRepository;
import com.gw2auth.oauth2.server.repository.application.client.ApplicationClientEntity;
import com.gw2auth.oauth2.server.repository.application.client.ApplicationClientRepository;
import com.gw2auth.oauth2.server.repository.application.client.account.ApplicationClientAccountEntity;
import com.gw2auth.oauth2.server.repository.application.client.account.ApplicationClientAccountRepository;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationEntity;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationRepository;
import com.gw2auth.oauth2.server.service.Clocked;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.application.AuthorizationCodeParamAccessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.*;
import java.util.function.Predicate;

@Service
public class ApplicationClientAccountServiceImpl implements ApplicationClientAccountService, OAuth2AuthorizationConsentService, Clocked {

    private static final Logger LOG = LoggerFactory.getLogger(ApplicationClientAccountServiceImpl.class);

    private final AccountService accountService;
    private final ApplicationAccountSubRepository applicationAccountSubRepository;
    private final ApplicationAccountRepository applicationAccountRepository;
    private final ApplicationClientRepository applicationClientRepository;
    private final ApplicationClientAccountRepository applicationClientAccountRepository;
    private final ApplicationClientAuthorizationRepository applicationClientAuthorizationRepository;
    private final AuthorizationCodeParamAccessor authorizationCodeParamAccessor;
    private Clock clock;

    @Autowired
    public ApplicationClientAccountServiceImpl(AccountService accountService,
                                               ApplicationAccountSubRepository applicationAccountSubRepository,
                                               ApplicationAccountRepository applicationAccountRepository,
                                               ApplicationClientRepository applicationClientRepository,
                                               ApplicationClientAccountRepository applicationClientAccountRepository,
                                               ApplicationClientAuthorizationRepository applicationClientAuthorizationRepository,
                                               AuthorizationCodeParamAccessor authorizationCodeParamAccessor) {

        this.accountService = accountService;
        this.applicationAccountSubRepository = applicationAccountSubRepository;
        this.applicationAccountRepository = applicationAccountRepository;
        this.applicationClientRepository = applicationClientRepository;
        this.applicationClientAccountRepository = applicationClientAccountRepository;
        this.applicationClientAuthorizationRepository = applicationClientAuthorizationRepository;
        this.authorizationCodeParamAccessor = authorizationCodeParamAccessor;
        this.clock = Clock.systemUTC();
    }

    @Override
    public void setClock(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public Optional<ApplicationClientAccount> getApplicationClientAccount(UUID accountId, UUID applicationClientId) {
        return this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(applicationClientId, accountId)
                .filter(ApplicationClientAccountServiceImpl::isAuthorized)
                .map(ApplicationClientAccount::fromEntity);
    }

    @Override
    public List<ApplicationClientAccount> getApplicationClientAccounts(UUID accountId) {
        return this.applicationClientAccountRepository.findAllByAccountId(accountId).stream()
                .filter(ApplicationClientAccountServiceImpl::isAuthorized)
                .map(ApplicationClientAccount::fromEntity)
                .toList();
    }

    @Override
    @Transactional
    public void deleteApplicationClientConsent(UUID accountId, UUID applicationClientId) {
        final ApplicationClientAccountEntity entity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(
                applicationClientId,
                accountId
        ).orElse(null);

        if (entity != null) {
            // delete this so authorizations are deleted
            this.applicationClientAccountRepository.deleteByApplicationClientIdAndAccountId(applicationClientId, accountId);
            this.applicationClientAccountRepository.save(new ApplicationClientAccountEntity(
                    entity.applicationClientId(),
                    entity.accountId(),
                    entity.applicationId(),
                    entity.approvalStatus(),
                    entity.approvalRequestMessage(),
                    Set.of()
            ));
        }
    }

    // region Spring OAuth2
    @Override
    @Transactional
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        if (!authorizationConsent.getScopes().containsAll(this.authorizationCodeParamAccessor.getRequestedScopes())) {
            throw this.authorizationCodeParamAccessor.error(new OAuth2Error(OAuth2ErrorCodes.INSUFFICIENT_SCOPE));
        }

        final UUID accountId = UUID.fromString(authorizationConsent.getPrincipalName());
        final UUID applicationClientId = UUID.fromString(authorizationConsent.getRegisteredClientId());

        ApplicationClientAccountEntity entity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(applicationClientId, accountId)
                .map((v) -> v.withAdditionalScopes(authorizationConsent.getScopes()))
                .orElseThrow();

        entity = this.applicationClientAccountRepository.save(entity);

        this.accountService.log(
                accountId,
                String.format("Updated consented oauth2-scopes to [%s]", String.join(", ", entity.authorizedScopes())),
                Map.of("application_id", entity.applicationId(), "client_id", entity.applicationClientId())
        );
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        final UUID accountId = UUID.fromString(authorizationConsent.getPrincipalName());
        final UUID applicationClientId = UUID.fromString(authorizationConsent.getRegisteredClientId());

        this.applicationClientAccountRepository.updateAuthorizedScopesByApplicationClientIdAndAccountId(
                applicationClientId,
                accountId,
                Set.of()
        );
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        final UUID accountId = UUID.fromString(principalName);
        final UUID applicationClientId = UUID.fromString(registeredClientId);
        final ApplicationClientEntity applicationClientEntity = this.applicationClientRepository.findById(applicationClientId).orElseThrow();
        this.applicationAccountSubRepository.findOrCreate(
                applicationClientEntity.applicationId(),
                accountId,
                UUID.randomUUID()
        );
        this.applicationAccountRepository.findOrCreate(
                applicationClientEntity.applicationId(),
                accountId,
                this.clock.instant()
        );

        if (this.authorizationCodeParamAccessor.isInCodeRequest() && !this.authorizationCodeParamAccessor.isInConsentContext()) {
            ApplicationClientAccountEntity entity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(applicationClientId, accountId).orElse(null);

            if (applicationClientEntity.requiresApproval()) {
                if (entity == null) {
                    entity = this.applicationClientAccountRepository.save(new ApplicationClientAccountEntity(
                            applicationClientId,
                            accountId,
                            applicationClientEntity.applicationId(),
                            ApplicationClientAccount.ApprovalStatus.PENDING.name(),
                            "Automatically generated message: the user tried to access this client",
                            Set.of()
                    ));
                }

                if (!entity.approvalStatus().equals(ApplicationClientAccount.ApprovalStatus.APPROVED.name())) {
                    throw this.authorizationCodeParamAccessor.error(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
                }
            } else {
                if (entity == null) {
                    entity = this.applicationClientAccountRepository.save(new ApplicationClientAccountEntity(
                            applicationClientId,
                            accountId,
                            applicationClientEntity.applicationId(),
                            ApplicationClientAccount.ApprovalStatus.APPROVED.name(),
                            "Automatically approved (no approval required)",
                            Set.of()
                    ));
                }
            }

            if (this.authorizationCodeParamAccessor.getAdditionalParameters().filter((e) -> e.getKey().equals("prompt")).map(Map.Entry::getValue).anyMatch(Predicate.isEqual("consent"))) {
                return null;
            }

            final String copyGw2AccountIdsFromClientAuthorizationId = this.applicationClientAuthorizationRepository.findLatestByAccountIdAndApplicationClientIdAndHavingScopes(accountId, applicationClientId, this.authorizationCodeParamAccessor.getRequestedScopes())
                    .map(ApplicationClientAuthorizationEntity::id)
                    .orElse(null);

            if (copyGw2AccountIdsFromClientAuthorizationId == null) {
                return null;
            }

            this.authorizationCodeParamAccessor.putValue("COPY_FROM_CLIENT_AUTHORIZATION_ID", copyGw2AccountIdsFromClientAuthorizationId);
        }

        return this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(applicationClientId, accountId)
                .filter(ApplicationClientAccountServiceImpl::isAuthorized)
                .map((entity) -> {
                    final OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(entity.applicationClientId().toString(), entity.accountId().toString());
                    entity.authorizedScopes().forEach(builder::scope);

                    return builder.build();
                })
                .orElse(null);
    }
    // endregion

    private static boolean isAuthorized(ApplicationClientAccountEntity entity) {
        return entity.approvalStatus().equals(ApplicationClientAccount.ApprovalStatus.APPROVED.name())
                && entity.authorizedScopes() != null
                && !entity.authorizedScopes().isEmpty();
    }
}
