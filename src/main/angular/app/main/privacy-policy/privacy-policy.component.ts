import { Component, OnInit } from '@angular/core';
import {faAngleDoubleDown, faAngleDoubleUp} from '@fortawesome/free-solid-svg-icons';

interface CookieInformation {
  name: string;
  type: string;
  expiration: string;
  description: string;
}

@Component({
  selector: 'app-privacy-policy',
  templateUrl: './privacy-policy.component.html',
  styleUrls: ['./privacy-policy.component.scss']
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
      name: 'cookie_consent_user_accepted',
      type: 'Strictly necessary',
      expiration: 'Expires',
      description: `
      Used to remember your decision of the Cookie-Consent Banner.
      `
    },
    {
      name: 'cookie_consent_level',
      type: 'Strictly necessary',
      expiration: 'Expires',
      description: `
      Used to remember which level of consent you authorized in the Preferences-Center.
      `
    }
  ];

  constructor() { }

  ngOnInit(): void {
  }

}
