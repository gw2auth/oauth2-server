import {Component, NgZone, OnInit} from '@angular/core';
import {OAuth2ConsentInformation, OAuth2ConsentService} from './oauth2-consent.service';
import {ActivatedRoute, Router} from '@angular/router';
import {catchError} from 'rxjs/operators';
import {of} from 'rxjs';
import {faCheck, faSync} from '@fortawesome/free-solid-svg-icons';
import {Gw2ApiService} from '../service/gw2-api.service';
import {Token} from '../service/token.model';


@Component({
  selector: 'app-oauth2-consent',
  templateUrl: './oauth2-consent.component.html',
  styleUrls: ['./oauth2-consent.component.scss']
})
export class OAuth2ConsentComponent implements OnInit {

  faCheck = faCheck;
  faSync = faSync;

  oauth2ConsentInformation: OAuth2ConsentInformation | null = null;
  gw2ApiTokenValidStatus = new Map<string, number>();
  selectedGw2AccountIds = new Set<string>();

  constructor(private readonly oauth2ConsentService: OAuth2ConsentService,
              private readonly gw2ApiService: Gw2ApiService,
              private readonly route: ActivatedRoute,
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
            for (let token of oauth2ConsentInformation.apiTokensWithSufficientPermissions) {
              this.updateApiTokenValidStatus(token);
            }

            this.oauth2ConsentInformation = oauth2ConsentInformation;
          }
        });
  }

  private updateApiTokenValidStatus(token: Token): void {
    if (!this.gw2ApiTokenValidStatus.has(token.gw2ApiToken)) {
      this.gw2ApiTokenValidStatus.set(token.gw2ApiToken, -1);

      this.gw2ApiService.getTokenInfo(token.gw2ApiToken)
          .pipe(catchError((e) => of(null)))
          .subscribe((gw2TokenInfo) => this.gw2ApiTokenValidStatus.set(token.gw2ApiToken, gw2TokenInfo == null ? 0 : 1));
    }
  }

  getApiTokenValidStatus(token: Token): number {
    const validStatus = this.gw2ApiTokenValidStatus.get(token.gw2ApiToken);
    return validStatus == undefined ? -1 : validStatus;
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
    const windowRef = window.open(url, '_blank');

    if (windowRef != null) {
      windowRef.addEventListener('message', (event) => {
        if (event.isTrusted && event.origin == location.origin) {
          this.zone.run(() => this.loadOAuth2ConsentInformation());
        }
      }, false);
    }
  }

  onSubmit(event: Event): void {
    (<HTMLFormElement>event.target).submit();
  }
}
