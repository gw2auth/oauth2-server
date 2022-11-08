import { Component, OnInit } from '@angular/core';
import {VerificationService} from './verification.service';
import {TokenService} from '../../../common/token.service';
import {VerificationChallenge, VerificationChallengeStart, VerificationChallengePending} from './verification.model';
import {faCheck, faBan} from '@fortawesome/free-solid-svg-icons';
import {ApiError, Gw2ApiPermission} from '../../../common/common.model';
import {Gw2ApiService} from '../../../common/gw2-api.service';
import {ToastService} from '../../../toast/toast.service';
import {DeleteModalComponent} from '../../../general/delete-modal.component';
import {firstValueFrom} from 'rxjs';
import {NgbModal} from '@ng-bootstrap/ng-bootstrap';


@Component({
  selector: 'app-verification',
  templateUrl: './verification.component.html'
})
export class VerificationComponent implements OnInit {

  faCheck = faCheck;
  faBan = faBan;

  gw2ApiPermissions: Gw2ApiPermission[] = Object.values(Gw2ApiPermission);

  availableChallenges: VerificationChallenge[] = [];
  startedChallenge: VerificationChallengeStart | null = null;
  pendingChallenges: VerificationChallengePending[] = [];

  constructor(private readonly verificationService: VerificationService,
              private readonly tokenService: TokenService,
              private readonly gw2ApiService: Gw2ApiService,
              private readonly modalService: NgbModal,
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

  canStartNewChallenge(): boolean {
    return this.startedChallenge == null || this.startedChallenge.nextAllowedStartTime.getTime() < Date.now();
  }

  openCancelPendingChallengeModal(challenge: VerificationChallengePending): void {
    const modalRef = this.modalService.open(DeleteModalComponent);
    modalRef.componentInstance.entityType = 'Pending challenge';
    modalRef.componentInstance.entityName = challenge.name;

    const gw2AccountId = challenge.gw2AccountId;

    modalRef.result
        .then((confirmed: boolean) => {
          if (confirmed) {
            challenge.cancellationInProgress = true;

            firstValueFrom(this.verificationService.cancelPendingChallenge(gw2AccountId))
                .then(() => {
                  this.toastService.show('Pending challenge cancelled', 'The pending challenge has been cancelled successfully');
                  this.pendingChallenges = this.pendingChallenges.filter((v) => v.gw2AccountId != gw2AccountId);
                })
                .catch((apiError: ApiError) => {
                  this.toastService.show('Pending challenge cancellation failed', 'The cancellation failed: ' + apiError.message);
                })
                .finally(() => {
                  challenge.cancellationInProgress = false;
                });
          }
        })
        .catch(() => {});
  }
}
