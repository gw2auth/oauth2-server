import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import {HttpClientModule} from '@angular/common/http';
import { LoginComponent } from './login/login.component';
import { AccountComponent } from './main/account/account.component';
import { HomeComponent } from './main/home/home.component';
import { HeaderComponent } from './main/header/header.component';
import { FooterComponent } from './main/footer/footer.component';
import { MainComponent } from './main/main.component';
import { TokenComponent } from './main/account/token/token.component';
import { SidebarComponent } from './main/account/sidebar/sidebar.component';
import {TokenService} from './service/token.service';
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
import {ClientAuthorizationService} from './main/account/application/client-authorization.service';
import {HTTP_INTERCEPTOR_PROVIDERS} from './http-inceptors';
import {Gw2ApiService} from './service/gw2-api.service';
import { VerificationComponent } from './main/account/verification/verification.component';
import {VerificationService} from './main/account/verification/verification.service';
import { PrivacyPolicyComponent } from './privacy-policy/privacy-policy.component';
import { SettingsComponent } from './main/account/settings/settings.component';
import {ButtonLoadableComponent} from './general/button-loadable.component';
import {AccountService} from './main/account/settings/account.service';

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
    ButtonLoadableComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    FontAwesomeModule,
    FormsModule,
    NgbModule
  ],
  providers: [HTTP_INTERCEPTOR_PROVIDERS, TokenService, ToastService, OAuth2ConsentService, ClientRegistrationService, ClientAuthorizationService, Gw2ApiService, VerificationService, AccountService],
  bootstrap: [AppComponent]
})
export class AppModule { }
