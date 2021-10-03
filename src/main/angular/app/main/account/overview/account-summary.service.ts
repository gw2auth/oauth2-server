import {Injectable} from "@angular/core";
import {HttpClient} from "@angular/common/http";
import {Observable} from 'rxjs';
import {AccountSummary} from './account-summary.model';

@Injectable()
export class AccountSummaryService {

    constructor(private readonly httpClient: HttpClient) {
    }

    getAccountSummary(): Observable<AccountSummary> {
        return this.httpClient.get<AccountSummary>('/api/account/summary');
    }
}