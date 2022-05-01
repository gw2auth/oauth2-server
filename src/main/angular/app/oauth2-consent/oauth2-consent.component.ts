import {Component, Inject, NgZone, OnInit} from '@angular/core';
import {MinimalToken, OAuth2ConsentInformation, OAuth2ConsentService} from './oauth2-consent.service';
import {ActivatedRoute, Router} from '@angular/router';
import {catchError} from 'rxjs/operators';
import {of} from 'rxjs';
import {faCheck, faSync, faTimesCircle} from '@fortawesome/free-solid-svg-icons';
import {Gw2ApiService} from '../common/gw2-api.service';
import {WINDOW} from '../app.module';
import {MessageEventData, Type} from '../common/window.model';


@Component({
  selector: 'app-oauth2-consent',
  templateUrl: './oauth2-consent.component.html'
})
export class OAuth2ConsentComponent implements OnInit {

  faCheck = faCheck;
  faSync = faSync;
  faTimesCircle = faTimesCircle;

  oauth2ConsentInformation: OAuth2ConsentInformation | null = null;
  gw2ApiTokenValidStatus = new Map<string, number>();
  selectedGw2AccountIds = new Set<string>();

  constructor(private readonly oauth2ConsentService: OAuth2ConsentService,
              private readonly gw2ApiService: Gw2ApiService,
              private readonly route: ActivatedRoute,
              @Inject(WINDOW) private readonly window: Window,
              private readonly router: Router,
              private readonly zone: NgZone) {

  }

  ngOnInit(): void {
    this.loadOAuth2ConsentInformation();
  }

  private loadOAuth2ConsentInformation(): void {
    this.oauth2ConsentService.getOAuth2ConsentInformation(this.route.snapshot.queryParams)
        .pipe(catchError((e) => of(null)))
        .subscribe((oauth2ConsentInformation: OAuth2ConsentInformation | null) => {
          if (oauth2ConsentInformation != null) {
            const autoSelectGw2AccountIds = new Set<string>(oauth2ConsentInformation.previouslyConsentedGw2AccountIds);

            for (let token of oauth2ConsentInformation.apiTokensWithSufficientPermissions) {
              this.updateApiTokenValidStatus(token, autoSelectGw2AccountIds.has(token.gw2AccountId));
            }

            this.oauth2ConsentInformation = oauth2ConsentInformation;
          }
        });
  }

  private updateApiTokenValidStatus(token: MinimalToken, autoSelect: boolean): void {
    if (!this.gw2ApiTokenValidStatus.has(token.gw2ApiToken)) {
      this.gw2ApiTokenValidStatus.set(token.gw2ApiToken, -1);

      this.gw2ApiService.getTokenInfo(token.gw2ApiToken)
          .pipe(catchError((e) => of(null)))
          .subscribe((gw2TokenInfo) => {
            this.gw2ApiTokenValidStatus.set(token.gw2ApiToken, gw2TokenInfo == null ? 0 : 1);

            if (gw2TokenInfo != null && autoSelect) {
              this.selectedGw2AccountIds.add(token.gw2AccountId);
            }
          });
    }
  }

  isApiTokenCheckInProgress(): boolean {
    let apiTokenCheckInProgress = false;

    for (let validStatus of this.gw2ApiTokenValidStatus.values()) {
      if (validStatus == undefined || validStatus == -1) {
        apiTokenCheckInProgress = true;
        break;
      }
    }

    return apiTokenCheckInProgress;
  }

  getApiTokenValidStatus(token: MinimalToken): number {
    const validStatus = this.gw2ApiTokenValidStatus.get(token.gw2ApiToken);
    return validStatus == undefined ? -1 : validStatus;
  }

  onSelectAllClick(): void {
    if (this.oauth2ConsentInformation) {
      for (let apiToken of this.oauth2ConsentInformation.apiTokensWithSufficientPermissions) {
        if (this.getApiTokenValidStatus(apiToken) == 1) {
          this.selectedGw2AccountIds.add(apiToken.gw2AccountId);
        }
      }
    }
  }

  onSelectNoneClick(): void {
    this.selectedGw2AccountIds.clear();
  }

  onSelectedGw2AccountChange(gw2AccountId: string): void {
    if (this.selectedGw2AccountIds.has(gw2AccountId)) {
      this.selectedGw2AccountIds.delete(gw2AccountId);
    } else {
      this.selectedGw2AccountIds.add(gw2AccountId);
    }
  }

  onManageTokensClick(event: Event): void {
    event.preventDefault();

    const url = this.router.serializeUrl(this.router.createUrlTree(['', 'account', 'token']));
    const windowRef = this.window.open(url, '_blank');

    if (windowRef != null) {
      this.window.addEventListener('message', (event: MessageEvent<MessageEventData<any>>) => {
        if (event.isTrusted && event.origin == this.window.location.origin) {
          if (event.data.type == Type.ADD_TOKEN || event.data.type == Type.UPDATE_TOKEN || event.data.type == Type.DELETE_TOKEN) {
            this.zone.run(() => this.loadOAuth2ConsentInformation());
          }
        }
      }, false);
    }
  }

  onSubmit(event: Event): void {
    (<HTMLFormElement>event.target).submit();
  }
}
