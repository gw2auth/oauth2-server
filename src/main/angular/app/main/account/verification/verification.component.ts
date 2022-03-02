import { Component, OnInit } from '@angular/core';
import {VerificationService} from './verification.service';
import {TokenService} from '../../../common/token.service';
import {
  VerificationChallenge,
  VerificationChallengePending,
  VerificationChallengeStart,
  ApiTokenNameMessage,
  TpBuyOrderMessage
} from './verification.model';
import {faCheck} from '@fortawesome/free-solid-svg-icons';
import {ApiError, Gw2ApiPermission} from '../../../common/common.model';
import {Token} from '../../../common/token.model';
import {Gw2ApiService} from '../../../common/gw2-api.service';
import {firstValueFrom, Observable, of} from 'rxjs';
import {catchError, map} from 'rxjs/operators';
import {ToastService} from '../../../toast/toast.service';


@Component({
  selector: 'app-verification',
  templateUrl: './verification.component.html'
})
export class VerificationComponent implements OnInit {

  faCheck = faCheck;

  gw2ApiPermissions: Gw2ApiPermission[] = Object.values(Gw2ApiPermission);

  availableChallenges: VerificationChallenge[] = [];
  startedChallenge: VerificationChallengeStart | null = null;
  pendingChallenges: VerificationChallengePending[] = [];
  tokens: Token[] = [];

  tpBuyOrderMessageObservableCache = new Map<any, Observable<{ gold: number, silver: number, copper: number, name: string, icon: string}>>();

  startChallengeInProgress = false;

  selectedGw2ApiToken: string | null = null;
  selectedTokenName: string | null = null;
  verificationSubmitInProgress = false;
  verificationNewApiToken = '';

  constructor(private readonly verificationService: VerificationService,
              private readonly tokenService: TokenService,
              private readonly gw2ApiService: Gw2ApiService,
              private readonly toastService: ToastService) { }

  ngOnInit(): void {
    this.verificationService.getBootstrap().subscribe((bootstrap) => {
      this.availableChallenges = bootstrap.availableChallenges;
      this.startedChallenge = bootstrap.startedChallenge;
      this.pendingChallenges = bootstrap.pendingChallenges;
    });

    this.tokenService.getTokens().subscribe((tokens) => this.tokens = tokens);
  }

  getChallengeName(id: number): string {
    switch (id) {
      case 1: return 'API-Token Name';
      case 2: return 'TP Buy-Order';
      default: return 'Unknown';
    }
  }

  canStartChallengeState(challenge: VerificationChallenge): number {
    if (this.startedChallenge != null) {
      if (this.startedChallenge.challengeId == challenge.id) {
        return 1;
      } else if (this.startedChallenge.nextAllowedStartTime.getTime() > Date.now()) {
        return 2;
      }
    }

    return 0;
  }

  asApiTokenMessage(message: Map<string, any>): string {
    return (<ApiTokenNameMessage><unknown>message).apiTokenName;
  }

  asTpBuyOrderMessage(message: Map<string, any>): Observable<{ gold: number, silver: number, copper: number, name: string, icon: string}> {
    let observable = this.tpBuyOrderMessageObservableCache.get(message);

    if (observable == undefined) {
      const tpBuyOrderMessage = <TpBuyOrderMessage><unknown>message;

      observable = this.gw2ApiService.getItem(tpBuyOrderMessage.gw2ItemId).pipe(
          map((gw2Item) => {
            let coins = tpBuyOrderMessage.buyOrderCoins;

            const copper = coins % 100;
            coins = (coins - copper) / 100;

            const silver = coins % 100;
            coins = (coins - silver) / 100;

            const icon = gw2Item.icon
                .replace('https://render.guildwars2.com/file/', 'https://icons-gw2.darthmaim-cdn.com/')
                .replace('.png', '-64px.png');

            return {gold: coins, silver: silver, copper: copper, name: gw2Item.name, icon: icon};
          }),
          catchError((e) => {
            return of({gold: 0, silver: 0, copper: 0, name: '', icon: ''});
          })
      );

      this.tpBuyOrderMessageObservableCache.set(message, observable);
    }

    return observable;
  }

  onStartChallengeClick(challenge: VerificationChallenge): void {
    this.startChallengeInProgress = true;

    firstValueFrom(this.verificationService.startChallenge(challenge.id))
        .then((response) => {
          this.startedChallenge = response;
          this.startChallengeInProgress = false;
        })
        .catch((apiError: ApiError) => {
          this.toastService.show('Failed to start challenge', apiError.message);
          this.startChallengeInProgress = false;
        })
  }

  onTokenSelectClick(token: Token): void {
    if (this.selectedGw2ApiToken == token.gw2ApiToken) {
      this.selectedGw2ApiToken = null;
      this.selectedTokenName = null;
      this.verificationNewApiToken = '';
    } else {
      this.selectedGw2ApiToken = token.gw2ApiToken;
      this.selectedTokenName = token.displayName;
      this.verificationNewApiToken = token.gw2ApiToken;
    }
  }

  onSubmitChallengeClick(challenge: VerificationChallengeStart): void {
    this.verificationSubmitInProgress = true;

    firstValueFrom(this.verificationService.submitChallenge(this.selectedGw2ApiToken!))
        .then((response) => {
          this.startedChallenge = null;

          if (!response.isSuccess) {
            this.pendingChallenges.push(response.pending!);
          }

          this.verificationSubmitInProgress = false;
        })
        .catch((apiError: ApiError) => {
          this.verificationSubmitInProgress = false;
          this.toastService.show('Failed to submit challenge', apiError.message);
        });
  }

  onUseNewApiTokenClick(): void {
    this.selectedGw2ApiToken = this.verificationNewApiToken;
    this.selectedTokenName = this.verificationNewApiToken;
  }
}
