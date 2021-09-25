import { Injectable } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor, HttpResponse
} from '@angular/common/http';
import { Observable } from 'rxjs';
import {map} from 'rxjs/operators';

@Injectable()
export class DateParsingInterceptor implements HttpInterceptor {

  constructor() {}

  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    return next.handle(request).pipe(map((event: HttpEvent<any>) => {
      if (event instanceof HttpResponse) {
        event = event.clone({ body: this.parseDates(event.body) });
      }

      return event;
    }));
  }

  private parseDates(body: any): any {
    if (body != null) {
      if (typeof body == 'object') {
        for (const k of Object.keys(body)) {
          body[k] = this.parseDates(body[k]);
        }
      } else if (body instanceof Array) {
        for (let i = 0; i < body.length; i++) {
          body[i] = this.parseDates(body[i]);
        }
      } else if (typeof body == 'string') {
        body = this.tryParseDate(body);
      }
    }

    return body;
  }

  private tryParseDate(value: string): string | Date {
    const date = new Date(value);

    if (date.toString() != 'Invalid Date') {
      const parsedISO = date.toISOString();

      if (value.startsWith(parsedISO.substring(0, parsedISO.length - 1))) {
        return date;
      }
    }

    return value;
  }
}
