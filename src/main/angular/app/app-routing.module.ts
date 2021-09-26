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

const routes: Routes = [
  {
    path: '',
    component: MainComponent,
    children: [
      { path: '', component: HomeComponent },
      { path: 'privacy-policy', component: PrivacyPolicyComponent },
      { path: 'legal', component: LegalComponent },
      {
        path: 'account',
        component: AccountComponent,
        canActivate: [AuthGuard],
        children: [
          { path: 'token', component: TokenComponent },
          { path: 'application', component: ApplicationComponent },
          { path: 'client', component: ClientComponent },
          { path: 'client/create', component: ClientCreateComponent },
          { path: 'verification', component: VerificationComponent },
          { path: 'settings', component: SettingsComponent },
        ]
      },
    ]
  },
  { path: 'login', component: LoginComponent, canActivate: [NonAuthGuard] },
  { path: 'oauth2/consent', component: OAuth2ConsentComponent, canActivate: [AuthGuard] }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
