import { Component, OnInit } from '@angular/core';
import {AuthService} from "../../auth.service";

@Component({
  selector: 'app-main-header',
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.scss']
})
export class HeaderComponent implements OnInit {

  isAuthenticated: boolean = false;

  constructor(private authService: AuthService) {
  }

  ngOnInit(): void {
    this.authService.isAuthenticated().subscribe((isAuthenticated) => this.isAuthenticated = isAuthenticated);
  }

  onLogoutClick(): void {
    this.authService.logout();
  }
}
