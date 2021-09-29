import {Component, OnInit} from '@angular/core';
import {AuthService} from '../../auth.service';
import {ColorSchemeService} from '../../service/color-scheme.service';
import {ColorScheme} from '../../service/color-scheme.model';


@Component({
  selector: 'app-main-header',
  templateUrl: './header.component.html'
})
export class HeaderComponent implements OnInit {

  SYSTEM = ColorScheme.SYSTEM;
  LIGHT = ColorScheme.LIGHT;
  DARK = ColorScheme.DARK;

  isAuthenticated: boolean = false;
  activeColorScheme = ColorScheme.SYSTEM;

  constructor(private readonly authService: AuthService, private readonly colorSchemeService: ColorSchemeService) {
  }

  ngOnInit(): void {
    this.authService.isAuthenticated().subscribe((isAuthenticated) => this.isAuthenticated = isAuthenticated);
    this.colorSchemeService.getPreferredColorScheme().subscribe((preferredColorScheme) => this.activeColorScheme = preferredColorScheme);
  }

  onAppearanceClick(value: ColorScheme): void {
    this.colorSchemeService.setPreferredColorScheme(value);
  }

  onLogoutClick(): void {
    this.authService.logout();
  }
}
