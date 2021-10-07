import {Component, OnDestroy, OnInit} from '@angular/core';
import {AuthService} from '../../auth.service';
import {ColorSchemeService} from '../../common/color-scheme.service';
import {ColorScheme} from '../../common/color-scheme.model';
import {Subscription} from 'rxjs';
import {NgbCollapse} from '@ng-bootstrap/ng-bootstrap';


@Component({
  selector: 'app-main-header',
  templateUrl: './header.component.html'
})
export class HeaderComponent implements OnInit, OnDestroy {

  SYSTEM = ColorScheme.SYSTEM;
  LIGHT = ColorScheme.LIGHT;
  DARK = ColorScheme.DARK;

  isAuthenticated: boolean = false;
  activeColorScheme = ColorScheme.SYSTEM;

  private subscriptions: Subscription[] = [];

  constructor(private readonly authService: AuthService, private readonly colorSchemeService: ColorSchemeService) {
  }

  ngOnInit(): void {
    this.subscriptions.push(
        this.authService.isAuthenticated().subscribe((isAuthenticated) => this.isAuthenticated = isAuthenticated),
        this.colorSchemeService.getPreferredColorScheme().subscribe((preferredColorScheme) => this.activeColorScheme = preferredColorScheme)
    );
  }

  ngOnDestroy(): void {
    for (let subscription of this.subscriptions) {
      subscription.unsubscribe();
    }

    this.subscriptions = [];
  }

  onAppearanceClick(value: ColorScheme): void {
    this.colorSchemeService.setPreferredColorScheme(value);
  }

  toggleIfShown(collapse: NgbCollapse): void {
    if (!collapse.collapsed) {
      collapse.toggle();
    }
  }

  onLoginClick(event: Event): void {
    event.preventDefault();
    this.authService.login();
  }

  onLogoutClick(): void {
    this.authService.logout();
  }
}
