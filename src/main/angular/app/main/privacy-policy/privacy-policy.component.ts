import { Component, OnInit } from '@angular/core';
import {faAngleDoubleDown, faAngleDoubleUp} from '@fortawesome/free-solid-svg-icons';

interface CookieInformation {
  name: string;
  type: string;
  expiration: string;
  description: string;
}

interface LocalStorageInformation {
  name: string;
  type: string;
  description: string;
}

@Component({
  selector: 'app-privacy-policy',
  templateUrl: './privacy-policy.component.html'
})
export class PrivacyPolicyComponent implements OnInit {

  faAngleDoubleDown = faAngleDoubleDown;
  faAngleDoubleUp = faAngleDoubleUp;

  cookieInformations: CookieInformation[] = [
    {
      name: 'JSESSIONID',
      type: 'Strictly necessary',
      expiration: 'Session',
      description: `
      The JSESSIONID is used to recognize you across multiple requests.
      It is only created if it is technically required to do so, for example when logging in.
      This Cookie is valid only for one Session, that means your Browser automatically deletes it once your close it.
      `
    },
    {
      name: 'XSRF-TOKEN',
      type: 'Strictly necessary',
      expiration: 'Session',
      description: `
      The XSRF-Token is used to offer a secure way to performing possibly mutating actions on the server.
      For example, if you want to create or delete something in your account, this Cookie is passed to the server to verify the action has been performed by you.
      This Cookie is valid only for one Session, that means your Browser automatically deletes it once your close it.
      `
    },
    {
      name: 'cookieconsent_status',
      type: 'Strictly necessary',
      expiration: '2 Years',
      description: `
      Used to remember your decision of the Cookie-Consent Banner on this device.
      `
    }
  ];

  localStorageInformations: LocalStorageInformation[] = [
    {
      name: 'GW2AUTH:PREFERRED_COLOR_SCHEME',
      type: 'Functional',
      description: `
      Used to remember your appearance choice on this device.
      `
    }
  ]

  constructor() { }

  ngOnInit(): void {
  }

}
