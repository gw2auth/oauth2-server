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
  activeAppearance = this.SYSTEM;

  constructor(@Inject(DOCUMENT) private readonly document: Document, private readonly authService: AuthService) {
  }

  ngOnInit(): void {
    this.authService.isAuthenticated().subscribe((isAuthenticated) => this.isAuthenticated = isAuthenticated);
  }

  onAppearanceClick(value: string): void {
    if (value != this.activeAppearance) {
      this.activeAppearance = value;

      this.document.documentElement.classList.remove('theme-light', 'theme-dark');

      switch (this.activeAppearance) {
        case this.DARK: {
          this.document.documentElement.classList.add('theme-dark');
          break;
        }
        case this.LIGHT: {
          this.document.documentElement.classList.add('theme-light');
          break;
        }
      }
    }
  }

  onLogoutClick(): void {
    this.authService.logout();
  }
}
