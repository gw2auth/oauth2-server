import {Injectable} from "@angular/core";
import {HttpClient} from "@angular/common/http";
import {Observable} from 'rxjs';
import {ApplicationSummary} from './application-summary.model';

@Injectable()
export class ApplicationSummaryService {

    constructor(private readonly httpClient: HttpClient) {
    }

    getApplicationSummary(): Observable<ApplicationSummary> {
        return this.httpClient.get<ApplicationSummary>('/api/application/summary');
    }
}