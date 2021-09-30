import {Component, Inject, OnDestroy, OnInit} from '@angular/core';
import {DOCUMENT} from '@angular/common';
import {ColorSchemeService} from './service/color-scheme.service';
import {ColorScheme} from './service/color-scheme.model';
import {NgcCookieConsentService} from 'ngx-cookieconsent';
import {Subscription} from "rxjs";
import {BrowserStorageService} from './service/browser-storage.service';
import {ConsentLevel} from './service/browser-storage.model';


@Component({
  selector: 'app-root',
  templateUrl: './app.component.html'
})
export class AppComponent implements OnInit, OnDestroy {

  private readonly themeSheetAnchor: HTMLLinkElement;
  private subscriptions: Subscription[] = [];

  constructor(@Inject(DOCUMENT) private readonly document: Document, private readonly colorSchemeService: ColorSchemeService, private readonly browserStorageService: BrowserStorageService, private readonly ccService: NgcCookieConsentService) {
    this.themeSheetAnchor = <HTMLLinkElement> this.document.getElementById('themeSheetAnchor');
  }

  ngOnInit(): void {
    this.subscriptions.push(
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

    if (this.ccService.hasAnswered() && this.ccService.hasConsented()) {
      this.browserStorageService.setAllowedConsentLevels(<ConsentLevel[]>Object.values(ConsentLevel));
    }

    this.subscriptions.push(
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
  }

  ngOnDestroy(): void {
    for (let subscription of this.subscriptions) {
      subscription.unsubscribe();
    }

    this.subscriptions = [];
  }
}
