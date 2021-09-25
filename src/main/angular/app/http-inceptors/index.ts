import { HTTP_INTERCEPTORS } from '@angular/common/http';
import {DateParsingInterceptor} from './date-parsing.interceptor';

export const HTTP_INTERCEPTOR_PROVIDERS = [
    { provide: HTTP_INTERCEPTORS, useClass: DateParsingInterceptor, multi: true },
];