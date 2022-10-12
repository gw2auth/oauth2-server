import { Component, OnInit } from '@angular/core';
import {VerificationService} from './verification.service';
import {TokenService} from '../../../common/token.service';
import {
  VerificationChallengeResponse,
  VerificationChallenge, VerificationChallengeStart, VerificationChallengePending
} from './verification.model';
import {faCheck} from '@fortawesome/free-solid-svg-icons';
import {Gw2ApiPermission} from '../../../common/common.model';
import {Gw2ApiService} from '../../../common/gw2-api.service';
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

  constructor(private readonly verificationService: VerificationService,
              private readonly tokenService: TokenService,
              private readonly gw2ApiService: Gw2ApiService,
              private readonly toastService: ToastService) { }

  ngOnInit(): void {
    this.verificationService.getBootstrap().subscribe((bootstrap) => {
      this.availableChallenges = bootstrap.availableChallenges.map((v) => this.verificationService.challengeFromResponse(v));

      if (bootstrap.startedChallenge == null) {
        this.startedChallenge = null;
      } else {
        this.startedChallenge = this.verificationService.challengeStartFromResponse(bootstrap.startedChallenge, this.availableChallenges);
      }

      this.tokenService.getTokens().subscribe((tokens) => {
        this.pendingChallenges = bootstrap.pendingChallenges.map((v) => this.verificationService.challengePendingFromResponse(v, tokens, this.availableChallenges));
      });
    });
  }

  canStartChallengeState(challenge: VerificationChallengeResponse): number {
    if (this.startedChallenge != null) {
      if (this.startedChallenge.challenge.id == challenge.id) {
        return 1;
      } else if (this.startedChallenge.nextAllowedStartTime.getTime() > Date.now()) {
        return 2;
      }
    }

    return 0;
  }

  canStartNewChallenge(): boolean {
    return this.startedChallenge == null || this.startedChallenge.nextAllowedStartTime.getTime() < Date.now();
  }
}
