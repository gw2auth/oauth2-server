import {Component, OnInit} from '@angular/core';
import {VerificationService} from './verification.service';
import {VerificationChallengeStart} from './verification.model';
import {TokenService} from '../../../common/token.service';
import {Token} from '../../../common/token.model';
import {firstValueFrom} from 'rxjs';
import {Router} from '@angular/router';
import {ToastService} from '../../../toast/toast.service';
import {Gw2ApiPermission} from '../../../common/common.model';
import {Gw2ApiService} from '../../../common/gw2-api.service';
import {faCheck} from '@fortawesome/free-solid-svg-icons';
import {SafeResourceUrl} from '@angular/platform-browser';


@Component({
    selector: 'app-verification-setup-submit',
    templateUrl: './verification-setup-submit.component.html'
})
export class VerificationSetupSubmitComponent implements OnInit {

    faCheck = faCheck;

    gw2ApiPermissions: Gw2ApiPermission[] = Object.values(Gw2ApiPermission);

    startedChallenge: VerificationChallengeStart | null = null;
    tokens: Token[] = [];

    verificationNewApiToken = '';
    verificationApiTokenInUse = '';
    verificationTokenType = '- Not yet selected -';
    verificationTokenName = '- Not yet selected -';
    verificationTokenGw2ApiPermissions: Gw2ApiPermission[] = [];
    verificationTokenCheckAvailable = false;
    tokenCheckInProgress = false;
    tokenCheckCheckedToken: string | null = null;
    submitInProgress = false;

    constructor(private readonly verificationService: VerificationService,
                private readonly tokenService: TokenService,
                private readonly gw2ApiService: Gw2ApiService,
                private readonly toastService: ToastService,
                private readonly router: Router) {
    }

    ngOnInit(): void {
        const startedChallengePromise = firstValueFrom(this.verificationService.getStartedChallenge());
        const availableChallengesPromise = firstValueFrom(this.verificationService.getAvailableChallenges());
        const tokensPromise = firstValueFrom(this.tokenService.getTokens());

        Promise.all([startedChallengePromise, availableChallengesPromise, tokensPromise])
            .then((values) => {
                const [startedChallengeResp, availableChallengeResps, tokens] = values;

                const challenges = availableChallengeResps.map((v) => this.verificationService.challengeFromResponse(v));
                const startedChallenge = this.verificationService.challengeStartFromResponse(startedChallengeResp, challenges);

                this.startedChallenge = startedChallenge;
                this.tokens = tokens
                    .filter((token) => !token.isVerified)
                    .filter((token) => {
                        for (let requiredGw2ApiPermission of startedChallenge.challenge.requiredGw2ApiPermissions) {
                            if (!token.gw2ApiPermissions.includes(requiredGw2ApiPermission)) {
                                return false;
                            }
                        }

                        return true;
                    });
            })
            .catch((e) => {
                this.toastService.show('Failed to retrieve data', 'The data could not be loaded. Please try again later: ' + e);
            });
    }

    hasYoutubeEmbedSrcs(v: VerificationChallengeStart, type: 'new' | 'existing'): boolean {
        const youtubeEmbedSrcs = v.challenge.youtubeEmbedSrcsByType.get(type);
        return youtubeEmbedSrcs != undefined && youtubeEmbedSrcs.length > 0;
    }

    getYoutubeEmbedSrcs(v: VerificationChallengeStart, type: 'new' | 'existing'): ReadonlyArray<SafeResourceUrl> {
        const youtubeEmbedSrcs = v.challenge.youtubeEmbedSrcsByType.get(type);
        return youtubeEmbedSrcs == undefined ? [] : youtubeEmbedSrcs;
    }

    onNewTokenChange(newApiToken: string): void {
        this.verificationApiTokenInUse = newApiToken;
        this.verificationTokenType = 'New';
        this.verificationTokenName = '- Not yet checked -';
        this.verificationTokenGw2ApiPermissions = [];
        this.verificationTokenCheckAvailable = true;
        this.tokenCheckCheckedToken = null;
    }

    onExistingTokenClick(token: Token): void {
        this.verificationNewApiToken = '';
        this.verificationApiTokenInUse = token.gw2ApiToken;
        this.verificationTokenType = 'Existing';
        this.verificationTokenName = token.displayName;
        this.verificationTokenGw2ApiPermissions = token.gw2ApiPermissions;
        this.verificationTokenCheckAvailable = false;
        this.tokenCheckCheckedToken = token.gw2ApiToken;
    }

    onTokenCheckClick(): void {
        const tokenToCheck = this.verificationApiTokenInUse;
        this.tokenCheckInProgress = true;

        const tokenInfoPromise = firstValueFrom(this.gw2ApiService.getTokenInfo(tokenToCheck));
        const accountPromise = firstValueFrom(this.gw2ApiService.getAccount(tokenToCheck));

        Promise.all([tokenInfoPromise, accountPromise])
            .then((results) => {
                const [tokenInfo, account] = results;

                // only set these values if the selection didnt change in the meantime
                if (tokenToCheck == this.verificationApiTokenInUse) {
                    this.verificationTokenName = account.name;
                    this.verificationTokenGw2ApiPermissions = tokenInfo.permissions;

                    let hasAllRequiredGw2ApiPermissions = true;

                    for (let gw2ApiPermission of this.startedChallenge!.challenge.requiredGw2ApiPermissions) {
                        if (!tokenInfo.permissions.includes(gw2ApiPermission)) {
                            hasAllRequiredGw2ApiPermissions = false;
                            break;
                        }
                    }

                    if (hasAllRequiredGw2ApiPermissions) {
                        this.tokenCheckCheckedToken = tokenToCheck;
                    }
                }
            })
            .catch((e) => {
                this.toastService.show('Token check failed', 'Failed to perform token check: ' + e?.text);
            })
            .finally(() => {
                this.tokenCheckInProgress = false;
            });
    }

    onBackToInstructionsClick(): void {
        this.router.navigate(['/', 'account', 'verification', 'setup', 'instructions']);
    }

    onChallengeSubmitClick(): void {
        this.submitInProgress = true;

        firstValueFrom(this.verificationService.submitChallenge(this.verificationApiTokenInUse))
            .then((result) => {
                if (result.isSuccess) {
                    this.toastService.show('Challenge succeeded', 'The challenge was successfully submitted and succeeded. Your account is now verified.', false);
                } else {
                    this.toastService.show('Challenge submitted', 'The challenge was successfully submitted and will be checked in the background.', false);
                }

                this.router.navigate(['/', 'account', 'verification']);
            })
            .catch((e) => {
                let errMsg: string;

                console.log(e);

                if (e?.message) {
                    errMsg = e.message;
                } else {
                    errMsg = JSON.stringify(e);
                }

                this.toastService.show('Submit failed', 'Failed to submit verification challenge: ' + errMsg);
            })
            .finally(() => {
                this.submitInProgress = false;
            });
    }
}