import {Inject, Injectable} from '@angular/core';
import {HttpClient, HttpResponse} from '@angular/common/http';
import {Observable, of, ReplaySubject, Subject} from 'rxjs';
import {catchError, map} from 'rxjs/operators';
import {Router} from '@angular/router';
import {WINDOW} from './app.module';
import {MessageEventData, Type} from './common/window.model';


@Injectable({
  providedIn: 'root'
})
export class AuthService {

  private readonly isAuthenticatedSubject: Subject<boolean>;
  private isInitial = true;

  constructor(@Inject(WINDOW) private readonly window: Window, private readonly http: HttpClient, private readonly router: Router) {
      this.isAuthenticatedSubject = new ReplaySubject<boolean>(1);
  }

  isAuthenticated(forceLookup: boolean = true): Observable<boolean> {
      if (forceLookup || this.isInitial) {
          this.isInitial = false;
          this.http.head('/api/authinfo', {observe: 'response'})
              .pipe(
                  map((resp: HttpResponse<any>) => resp.status >= 200 && resp.status < 300),
                  catchError((err) => of(false))
              )
              .subscribe((resp) => this.next(resp));
      }

      return this.isAuthenticatedSubject.asObservable();
  }

  login(): void {
      const LOGIN = ['login'];

      if (this.window.opener == null) {
          const url = this.router.serializeUrl(this.router.createUrlTree(LOGIN));
          const windowRef = this.window.open(url, '_blank');

          if (windowRef != null) {
              const handler = (event: MessageEvent<MessageEventData<any>>) => {
                  if (event.isTrusted && event.origin == this.window.location.origin) {
                      if (event.data.type == Type.AUTHENTICATION) {
                          if ((<MessageEventData<boolean>> event.data).payload) {
                              this.next(true);
                              this.window.removeEventListener('message', handler, false);
                              windowRef.close();
                          }
                      }
                  }
              };

              this.window.addEventListener('message', handler, false);
          }
      } else {
          this.router.navigate(LOGIN);
      }
  }

  logout(navigateTo: string | null = '/'): void {
      this.http.post('/auth/logout', null, {observe: 'response'})
          .pipe(
              // 2xx codes -> logout success, 403 -> was already logged out
              map((resp: HttpResponse<any>) => resp.status >= 200 && resp.status < 300),
              catchError((err) => of(err.status == 401 || err.status == 403))
          )
          .subscribe((resp) => {
              if (resp) {
                  this.next(false);

                  if (navigateTo != null) {
                      this.router.navigateByUrl(navigateTo);
                  }
              }
          });
  }

  private next(isAuthenticated: boolean): void {
      this.isAuthenticatedSubject.next(isAuthenticated);

      if (this.window.opener != null) {
          this.window.opener.postMessage(new MessageEventData<boolean>(Type.AUTHENTICATION, isAuthenticated), this.window.location.origin);
      }
  }
}
