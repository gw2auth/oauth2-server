import { Component, OnInit } from '@angular/core';
import {faAngleDoubleDown, faAngleDoubleUp} from '@fortawesome/free-solid-svg-icons';

interface CookieInformation {
  name: string;
  scope: string;
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
      scope: 'Session',
      description: `
      The JSESSIONID is used to recognize you across multiple requests.
      For example, without a JSESSIONID, we could not know if you're currently logged in.
      It is also required in combination with the XSRF-Token Cookie to offer a secure way of communicating with our server.
      This Cookie is valid only for one Session, that means your Browser automatically deletes it once you close all open Tabs of this website.
      `
    },
    {
      name: 'XSRF-TOKEN',
      scope: 'Session',
      description: `
      The XSRF-Token is used to offer a secure way to performing possibly mutating actions on the server.
      For example, if you want to create or delete something in your account, this Cookie is passed to the server to verify the action has been performed by you.
      `
    },
    {
      name: 'cookie_consent_user_accepted',
      scope: 'Expires',
      description: `
      This Cookie is used to remember your decision of the Cookie-Consent Banner.
      `
    },
    {
      name: 'cookie_consent_level',
      scope: 'Expires',
      description: `
      This Cookie is used to remember which level of consent you authorized in the Preferences-Center.
      `
    }
  ];

  constructor() { }

  ngOnInit(): void {
  }

}
