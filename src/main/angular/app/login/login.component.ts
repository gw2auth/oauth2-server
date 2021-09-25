import { Component, OnInit } from '@angular/core';
import {faGithub, faGoogle} from '@fortawesome/free-brands-svg-icons';
import {faUserShield} from '@fortawesome/free-solid-svg-icons';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {

  faGithub = faGithub;
  faGoogle = faGoogle;
  faUserShield = faUserShield;

  constructor() { }

  ngOnInit(): void {
  }
}
