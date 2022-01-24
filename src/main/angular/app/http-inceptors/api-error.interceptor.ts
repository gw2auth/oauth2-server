import {Injectable} from '@angular/core';
import {
    HttpRequest,
    HttpHandler,
    HttpEvent,
    HttpInterceptor, HttpErrorResponse
} from '@angular/common/http';
import {Observable, throwError} from 'rxjs';
import {catchError} from 'rxjs/operators';
import {ApiError} from '../common/common.model';

@Injectable()
export class ApiErrorInterceptor implements HttpInterceptor {

    constructor() {}

    intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        return next.handle(request).pipe(catchError((error: HttpErrorResponse) => {
            if (error.status >= 400 && error.error) {
                return throwError(() => error.error as ApiError);
            }

            return throwError(() => error);
        }));
    }
}
