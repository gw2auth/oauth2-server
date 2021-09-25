import { Component, OnInit } from '@angular/core';
import {VerificationService} from '../../../service/verification.service';
import {TokenService} from '../../../service/token.service';
import {VerificationChallenge, VerificationChallengePending, VerificationChallengeStart} from '../../../service/verification.model';
import {faAngleDoubleUp, faAngleDoubleDown, faCheck} from '@fortawesome/free-solid-svg-icons';
import {Gw2ApiPermission} from '../../../service/general.model';
import {Token} from '../../../service/token.model';


@Component({
  selector: 'app-verification',
  templateUrl: './verification.component.html',
  styleUrls: ['./verification.component.scss']
})
export class VerificationComponent implements OnInit {

  faAngleDoubleUp = faAngleDoubleUp;
  faAngleDoubleDown = faAngleDoubleDown;
  faCheck = faCheck;

  gw2ApiPermissions: Gw2ApiPermission[] = Object.values(Gw2ApiPermission);

  availableChallenges: VerificationChallenge[] = [];
  startedChallenge: VerificationChallengeStart | null = null;
  pendingChallenges: VerificationChallengePending[] = [];
  tokens: Token[] = [];

  startChallengeInProgress = false;

  selectedGw2ApiToken: string | null = null;
  verificationSubmitInProgress = false;
  verificationNewApiToken = '';

  constructor(private readonly verificationService: VerificationService, private readonly tokenService: TokenService) { }

  ngOnInit(): void {
    this.verificationService.getBootstrap().subscribe((bootstrap) => {
      this.availableChallenges = bootstrap.availableChallenges;
      this.startedChallenge = bootstrap.startedChallenge;
      this.pendingChallenges = bootstrap.pendingChallenges;
    });

    this.tokenService.getTokens().subscribe((tokens) => this.tokens = tokens);
  }

  onStartChallengeClick(challenge: VerificationChallenge): void {
    this.startChallengeInProgress = true;

    this.verificationService.startChallenge(challenge.id).subscribe((verificationChallengeStart) => {
      this.startedChallenge = verificationChallengeStart;
      this.startChallengeInProgress = false;
    });
  }

  onTokenSelectClick(token: Token): void {
    if (this.selectedGw2ApiToken == token.gw2ApiToken) {
      this.selectedGw2ApiToken = null;
    } else {
      this.selectedGw2ApiToken = token.gw2ApiToken;
    }
  }

  onSubmitChallengeClick(challenge: VerificationChallengeStart): void {
    this.verificationSubmitInProgress = true;

    this.verificationService.submitChallenge(this.selectedGw2ApiToken!).subscribe((verificationChallengeSubmit) => {
      this.startedChallenge = null;

      if (!verificationChallengeSubmit.isSuccess) {
        this.pendingChallenges.push(verificationChallengeSubmit.pending!);
      }

      this.verificationSubmitInProgress = false;
    });
  }

  onUseNewApiTokenClick(): void {
    this.selectedGw2ApiToken = this.verificationNewApiToken;
  }
}
