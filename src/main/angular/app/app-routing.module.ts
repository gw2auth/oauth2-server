import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { LoginComponent } from './login/login.component';
import {AuthGuard} from './auth.guard';
import {NonAuthGuard} from './non-auth.guard';
import {AccountComponent} from './main/account/account.component';
import {HomeComponent} from './main/home/home.component';
import {MainComponent} from './main/main.component';
import {TokenComponent} from './main/account/token/token.component';
import {OAuth2ConsentComponent} from './oauth2-consent/oauth2-consent.component';
import {ClientComponent} from './main/account/client/client.component';
import {ClientCreateComponent} from './main/account/client/client-create.component';
import {ApplicationComponent} from './main/account/application/application.component';
import {VerificationComponent} from './main/account/verification/verification.component';
import {PrivacyPolicyComponent} from './main/privacy-policy/privacy-policy.component';
import {SettingsComponent} from './main/account/settings/settings.component';
import {LegalComponent} from './main/legal/legal.component';
import {ClientDebugComponent} from './main/account/client/client-debug.component';
import {ClientDebugResponseComponent} from './main/account/client/client-debug-response.component';
import {OverviewComponent} from './main/account/overview/overview.component';
import {VerificationSetupSelectComponent} from './main/account/verification/verification-setup-select.component';
import {VerificationSetupInstructionsComponent} from './main/account/verification/verification-setup-instructions.component';
import {VerificationSetupSubmitComponent} from './main/account/verification/verification-setup-submit.component';

const routes: Routes = [
  {
    path: '',
    component: MainComponent,
    children: [
      { path: '', component: HomeComponent},
      { path: 'privacy-policy', component: PrivacyPolicyComponent, data: { title: 'Privacy Policy' } },
      { path: 'legal', component: LegalComponent, data: { title: 'Legal' } },
      {
        path: 'account',
        component: AccountComponent,
        canActivate: [AuthGuard],
        data: { title: 'Account' },
        children: [
          { path: '', component: OverviewComponent },
          { path: 'token', component: TokenComponent, data: { title: 'API Tokens' } },
          { path: 'application', component: ApplicationComponent, data: { title: 'Applications' } },
          { path: 'client', component: ClientComponent, data: { title: 'Clients' } },
          { path: 'client/create', component: ClientCreateComponent, data: { title: 'Create Client' } },
          { path: 'client/debug', component: ClientDebugResponseComponent, data: { title: 'Debug Client' } },
          { path: 'client/:clientId/debug', component: ClientDebugComponent, data: { title: 'Debug Client' } },
          { path: 'verification', component: VerificationComponent, data: { title: 'Verification' } },
          { path: 'verification/setup/select', component: VerificationSetupSelectComponent, data: { title: 'Verification' } },
          { path: 'verification/setup/instructions', component: VerificationSetupInstructionsComponent, data: { title: 'Verification' } },
          { path: 'verification/setup/submit', component: VerificationSetupSubmitComponent, data: { title: 'Verification' } },
          { path: 'settings', component: SettingsComponent, data: { title: 'Settings' } },
        ]
      },
    ]
  },
  { path: 'login', component: LoginComponent, canActivate: [NonAuthGuard], data: { title: 'Login' } },
  { path: 'oauth2-consent', component: OAuth2ConsentComponent, canActivate: [AuthGuard], data: { title: 'Authorize' } }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
