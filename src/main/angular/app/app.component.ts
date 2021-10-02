import {Component, Inject, OnDestroy, OnInit} from '@angular/core';
import {DOCUMENT} from '@angular/common';
import {ColorSchemeService} from './common/color-scheme.service';
import {ColorScheme} from './common/color-scheme.model';
import {NgcCookieConsentService} from 'ngx-cookieconsent';
import {Subscription} from "rxjs";
import {BrowserStorageService} from './common/browser-storage.service';
import {ConsentLevel} from './common/browser-storage.model';
import {ActivatedRoute, ActivatedRouteSnapshot, NavigationEnd, Router, RouterStateSnapshot} from '@angular/router';
import {Title} from '@angular/platform-browser';
import {filter, map} from 'rxjs/operators';


@Component({
  selector: 'app-root',
  templateUrl: './app.component.html'
})
export class AppComponent implements OnInit, OnDestroy {

  private readonly themeSheetAnchor: HTMLLinkElement;
  private subscription = new Subscription();

  constructor(@Inject(DOCUMENT) private readonly document: Document,
              private readonly colorSchemeService: ColorSchemeService,
              private readonly browserStorageService: BrowserStorageService,
              private readonly ccService: NgcCookieConsentService,
              private readonly router: Router,
              private readonly titleService: Title) {

    this.themeSheetAnchor = <HTMLLinkElement> this.document.getElementById('themeSheetAnchor');
  }

  ngOnInit(): void {
    // region title
    this.subscription.add(
        this.router.events
            .pipe(
                filter((event) => event instanceof NavigationEnd),
                map((event) => <NavigationEnd> event)
            )
            .subscribe((event) => {
                let routeSnapshot: ActivatedRouteSnapshot | null = this.router.routerState.snapshot.root;
                let title = null;

                // find the first route with a title, starting from the current route down to the root
                while (routeSnapshot != null) {
                    if (routeSnapshot.data && routeSnapshot.data.title) {
                        title = routeSnapshot.data.title;
                    }

                    routeSnapshot = routeSnapshot.firstChild;
                }

                if (title != null) {
                    title = 'GW2Auth - ' + title;
                } else {
                    title = 'GW2Auth';
                }

                this.titleService.setTitle(title);
            })
    );
    // endregion

    // region color scheme
    this.subscription.add(
        this.colorSchemeService.getInferredPreferredColorScheme().subscribe((colorScheme) => {
          let themeSheetToApply = this.themeSheetAnchor.href;

          switch (colorScheme) {
            case ColorScheme.LIGHT: {
              themeSheetToApply = '/light.css';
              break;
            }
            case ColorScheme.DARK: {
              themeSheetToApply = '/dark.css';
              break;
            }
          }

          if (themeSheetToApply != this.themeSheetAnchor.href) {
            this.themeSheetAnchor.href = themeSheetToApply;
          }
        })
    );
    // endregion

    // region cookie consent
    if (this.ccService.hasAnswered() && this.ccService.hasConsented()) {
      this.browserStorageService.setAllowedConsentLevels(<ConsentLevel[]>Object.values(ConsentLevel));
    }

    this.subscription.add(
        this.ccService.statusChange$.subscribe((e) => {
          switch (e.status) {
            case 'allow':
            case 'dismiss': {
              this.browserStorageService.setAllowedConsentLevels(<ConsentLevel[]>Object.values(ConsentLevel));
              break;
            }
            case 'deny': {
              this.browserStorageService.setAllowedConsentLevels([ConsentLevel.STRICTLY_NECESSARY]);
              break;
            }
          }
        })
    );
    // endregion
  }

  ngOnDestroy(): void {
    const sub = this.subscription;
    this.subscription = new Subscription();

    sub.unsubscribe();
  }
}
