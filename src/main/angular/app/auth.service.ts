import { Injectable } from '@angular/core';
import {HttpClient, HttpResponse} from '@angular/common/http';
import {Observable, of, ReplaySubject, Subject} from 'rxjs';
import {catchError, map} from 'rxjs/operators';
import {Router} from '@angular/router';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  private readonly isAuthenticatedSubject: Subject<boolean>;
  private isInitial = true;

  constructor(private readonly http: HttpClient, private readonly router: Router) {
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
              .subscribe((resp) => this.isAuthenticatedSubject.next(resp));
      }

      return this.isAuthenticatedSubject.asObservable();
  }

  logout(): void {
      this.http.post('/logout', null, {observe: 'response'})
          .pipe(
              // 2xx codes -> logout success, 403 -> was already logged out
              map((resp: HttpResponse<any>) => (resp.status >= 200 && resp.status < 300) || resp.status == 403),
              catchError((err) => of(false))
          )
          .subscribe((resp) => {
              if (resp) {
                  this.isAuthenticatedSubject.next(false);
                  this.router.navigateByUrl('/');
              }
          });
  }
}
