import {Inject, Injectable} from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor, HttpErrorResponse
} from '@angular/common/http';
import {Observable, throwError} from 'rxjs';
import {catchError} from 'rxjs/operators';
import {DOCUMENT} from '@angular/common';
import {AuthService} from '../auth.service';

@Injectable()
export class UnauthenticatedInterceptor implements HttpInterceptor {

  constructor(@Inject(DOCUMENT) private readonly document: Document, private readonly authService: AuthService) {}

  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    return next.handle(request).pipe(catchError((error: HttpErrorResponse) => {
      if (error.status == 401 || error.status == 403) {
        if (error.url != null && this.shouldHandleURL(error.url)) {
          this.authService.logout('/login');
        }
      }

      return throwError(() => error);
    }));
  }

  private shouldHandleURL(url: string): boolean {
    let suffix: string | null = null;

    if (url.startsWith('/')) {
      suffix = url;
    } else if (url.startsWith(this.document.location.origin)) {
      suffix = url.substring(this.document.location.origin.length);
    }

    return suffix != null && suffix.startsWith('/api') && !suffix.startsWith('/api/authinfo') && !suffix.startsWith('/api/oauth2/token');
  }
}
