import {Component, OnInit} from '@angular/core';
import {VerificationService} from './verification.service';
import {
    VerificationChallenge,
    VerificationChallengeStart
} from './verification.model';
import {Gw2ApiPermission} from '../../../common/common.model';
import {Router} from '@angular/router';
import {ToastService} from '../../../toast/toast.service';
import {catchError} from 'rxjs/operators';
import {of} from 'rxjs';


@Component({
    selector: 'app-verification-setup-select',
    templateUrl: './verification-setup-select.component.html'
})
export class VerificationSetupSelectComponent implements OnInit {

    gw2ApiPermissions: Gw2ApiPermission[] = Object.values(Gw2ApiPermission);

    availableChallenges: VerificationChallenge[] = [];
    startedChallenge: VerificationChallengeStart | null = null;

    isLoading = false;

    constructor(private readonly verificationService: VerificationService,
                private readonly toastService: ToastService,
                private readonly router: Router) {
    }

    ngOnInit(): void {
        this.verificationService.getBootstrap().subscribe((bootstrap) => {
            this.availableChallenges = bootstrap.availableChallenges.map((v) => this.verificationService.challengeFromResponse(v));

            if (bootstrap.startedChallenge == null) {
                this.startedChallenge = null;
            } else {
                this.startedChallenge = this.verificationService.challengeStartFromResponse(bootstrap.startedChallenge, this.availableChallenges);
            }
        });
    }

    onProceedClick(challenge: VerificationChallenge): void {
        this.isLoading = true;
        this.verificationService.startChallenge(challenge.id)
            .pipe(catchError((e) => {
                this.toastService.show('Failed to start challenge', e);
                return of(null);
            }))
            .subscribe((r) => {
                this.isLoading = false;

                if (r != null) {
                    this.router.navigate(['/', 'account', 'verification', 'setup', 'instructions']);
                }
            });
    }
}