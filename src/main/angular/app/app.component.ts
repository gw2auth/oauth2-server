import {Component, Inject, OnInit} from '@angular/core';
import {DOCUMENT} from '@angular/common';
import {ColorSchemeService} from './service/color-scheme.service';
import {ColorScheme} from './service/color-scheme.model';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html'
})
export class AppComponent implements OnInit {

  private readonly themeSheetAnchor: HTMLLinkElement;

  constructor(@Inject(DOCUMENT) private readonly document: Document, private readonly colorSchemeService: ColorSchemeService) {
    this.themeSheetAnchor = <HTMLLinkElement> this.document.getElementById('themeSheetAnchor');
  }

  ngOnInit(): void {
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
    });
  }
}
