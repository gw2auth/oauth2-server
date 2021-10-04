import { HTTP_INTERCEPTORS } from '@angular/common/http';
import {DateParsingInterceptor} from './date-parsing.interceptor';
import {UnauthenticatedInterceptor} from './unauthenticated.interceptor';

export const HTTP_INTERCEPTOR_PROVIDERS = [
    { provide: HTTP_INTERCEPTORS, useClass: UnauthenticatedInterceptor, multi: true },
    { provide: HTTP_INTERCEPTORS, useClass: DateParsingInterceptor, multi: true }
];