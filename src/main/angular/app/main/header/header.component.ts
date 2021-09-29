import {Component, Inject, OnInit} from '@angular/core';
import {AuthService} from "../../auth.service";
import {DOCUMENT} from '@angular/common';


@Component({
  selector: 'app-main-header',
  templateUrl: './header.component.html'
})
export class HeaderComponent implements OnInit {

  readonly SYSTEM = 'system';
  readonly LIGHT = 'light';
  readonly DARK = 'dark';

  isAuthenticated: boolean = false;

  themeAnchorElement: HTMLLinkElement;
  activeAppearance = this.SYSTEM;

  constructor(@Inject(DOCUMENT) private readonly document: Document, private readonly authService: AuthService) {
    this.themeAnchorElement = <HTMLLinkElement>this.document.getElementById('themeSheetAnchor');
  }

  ngOnInit(): void {
    this.authService.isAuthenticated().subscribe((isAuthenticated) => this.isAuthenticated = isAuthenticated);
  }

  onAppearanceClick(value: string): void {
    if (value != this.activeAppearance) {
      this.activeAppearance = value;

      let applyAppearance = this.activeAppearance;

      if (this.activeAppearance == this.SYSTEM) {
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
          applyAppearance = this.LIGHT;
        } else {
          applyAppearance = this.DARK;
        }
      }

      switch (applyAppearance) {
        case this.LIGHT: {
          this.themeAnchorElement.href = '/light.css';
          break;
        }
        case this.DARK: {
          this.themeAnchorElement.href = '/dark.css';
          break;
        }
      }
    }
  }

  onLogoutClick(): void {
    this.authService.logout();
  }
}
