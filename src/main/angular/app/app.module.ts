import {InjectionToken, NgModule} from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import {HttpClientModule} from '@angular/common/http';
import { LoginComponent } from './login/login.component';
import { AccountComponent } from './main/account/account.component';
import { HomeComponent } from './main/home/home.component';
import { HeaderComponent } from './main/header/header.component';
import { FooterComponent } from './footer/footer.component';
import { MainComponent } from './main/main.component';
import { TokenComponent } from './main/account/token/token.component';
import { SidebarComponent } from './main/account/sidebar/sidebar.component';
import {TokenService} from './common/token.service';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import {FormsModule} from '@angular/forms';
import { NgbModule } from '@ng-bootstrap/ng-bootstrap';
import { ToastComponent } from './toast/toast.component';
import {ToastService} from './toast/toast.service';
import { OAuth2ConsentComponent } from './oauth2-consent/oauth2-consent.component';
import {OAuth2ConsentService} from './oauth2-consent/oauth2-consent.service';
import {EditTokenComponent} from './main/account/token/edit-token.component';
import {ClientRegistrationService} from './main/account/client/client-registration.service';
import {Gw2ApiPermissionBadgeComponent} from './general/gw2-api-permission-badge.component';
import { ClientComponent } from './main/account/client/client.component';
import {InputCopyableComponent} from './general/input-copyable.component';
import { ClientCreateComponent } from './main/account/client/client-create.component';
import {DeleteModalComponent} from "./general/delete-modal.component";
import { ApplicationComponent } from './main/account/application/application.component';
import {ClientConsentService} from './main/account/application/client-consent.service';
import {HTTP_INTERCEPTOR_PROVIDERS} from './http-inceptors';
import {Gw2ApiService} from './common/gw2-api.service';
import { VerificationComponent } from './main/account/verification/verification.component';
import {VerificationService} from './main/account/verification/verification.service';
import { PrivacyPolicyComponent } from './main/privacy-policy/privacy-policy.component';
import { SettingsComponent } from './main/account/settings/settings.component';
import {ButtonLoadableComponent} from './general/button-loadable.component';
import {AccountService} from './main/account/settings/account.service';
import { LegalComponent } from './main/legal/legal.component';
import { ClientDebugComponent } from './main/account/client/client-debug.component';
import {ClientDebugResponseComponent} from './main/account/client/client-debug-response.component';
import {Oauth2ClientService} from './main/account/client/oauth2-client.service';
import {BrowserStorageService} from './common/browser-storage.service';
import {ColorSchemeService} from './common/color-scheme.service';
import {NgcCookieConsentConfig, NgcCookieConsentModule} from 'ngx-cookieconsent';
import { OverviewComponent } from './main/account/overview/overview.component';
import {AccountSummaryService} from './main/account/overview/account-summary.service';
import {SummaryElementComponent} from './general/summary-element.component';
import {ApplicationSummaryService} from './main/home/application-summary.service';
import {DeleteAbstractModalComponent} from './general/delete-abstract-modal.component';
import {DeleteTokenModalComponent} from './main/account/token/delete-token-modal.component';
import {DeleteApplicationModalComponent} from './main/account/application/delete-application-modal.component';
import { FaqComponent } from './main/faq/faq.component';
import {ClientAuthorizationService} from './main/account/application/client-authorization.service';
import {DeleteAuthorizationModalComponent} from './main/account/application/delete-authorization-modal.component';
import {AuthorizationModalComponent} from './main/account/application/authorization-modal.component';
import {RegenerateClientSecretModalComponent} from './main/account/client/regenerate-client-secret-modal.component';
import {LogoComponent} from './general/logo.component';
import {VerificationSetupSelectComponent} from './main/account/verification/verification-setup-select.component';
import {VerificationSetupInstructionsComponent} from './main/account/verification/verification-setup-instructions.component';
import {VerificationSetupSubmitComponent} from './main/account/verification/verification-setup-submit.component';
import {TextCopyableComponent} from './general/text-copyable.component';
import {AccountLogService} from './common/account-log.service';


export const WINDOW = new InjectionToken<Window>('Window', {
  providedIn: 'root',
  factory: () => window
});

const cookieConfig: NgcCookieConsentConfig = {
  cookie: {
    domain: ''
  },
  palette: {
    popup: {
      background: '#000'
    },
    button: {
      background: '#f1d600'
    }
  },
  position: 'bottom-right',
  theme: 'edgeless',
  type: 'opt-out',
  layout: 'custom',
  layouts: {'custom': '{{message}}{{compliance}}'},
  elements:{
    message: `
    <span id="cookieconsent:desc" class="cc-message">
      {{message}}<a aria-label="learn more about our privacy policy" tabindex="1" class="cc-link" href="{{privacyPolicyHref}}" target="_blank">{{privacyPolicyText}}</a>
    </span>
    `,
  },
  content:{
    message: `This website uses Cookies and Local Storage to offer you the best possible experience. Find out more in our `,

    privacyPolicyText: 'Privacy Policy',
    privacyPolicyHref: '/privacy-policy'
  }
};


@NgModule({
  declarations: [
    AppComponent,
    LoginComponent,
    AccountComponent,
    HomeComponent,
    HeaderComponent,
    FooterComponent,
    MainComponent,
    TokenComponent,
    SidebarComponent,
    ToastComponent,
    OAuth2ConsentComponent,
    EditTokenComponent,
    DeleteAbstractModalComponent,
    DeleteModalComponent,
    Gw2ApiPermissionBadgeComponent,
    ClientComponent,
    InputCopyableComponent,
    ClientCreateComponent,
    ApplicationComponent,
    VerificationComponent,
    PrivacyPolicyComponent,
    LoginComponent,
    SettingsComponent,
    ButtonLoadableComponent,
    LegalComponent,
    ClientDebugComponent,
    ClientDebugResponseComponent,
    OverviewComponent,
    SummaryElementComponent,
    DeleteTokenModalComponent,
    DeleteApplicationModalComponent,
    FaqComponent,
    DeleteAuthorizationModalComponent,
    AuthorizationModalComponent,
    RegenerateClientSecretModalComponent,
    LogoComponent,
    VerificationSetupSelectComponent,
    VerificationSetupInstructionsComponent,
    VerificationSetupSubmitComponent,
    TextCopyableComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    FontAwesomeModule,
    FormsModule,
    NgbModule,
    NgcCookieConsentModule.forRoot(cookieConfig)
  ],
  providers: [
    HTTP_INTERCEPTOR_PROVIDERS,
    TokenService,
    ToastService,
    OAuth2ConsentService,
    ClientRegistrationService,
    ClientConsentService,
    ClientAuthorizationService,
    Gw2ApiService,
    VerificationService,
    AccountService,
    Oauth2ClientService,
    BrowserStorageService,
    ColorSchemeService,
    AccountSummaryService,
    ApplicationSummaryService,
    AccountLogService
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
