import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Observable} from 'rxjs';
import {Gw2Account, Gw2Item, Gw2TokenInfo} from './gw2-api.model';

@Injectable({
    providedIn: 'root'
})
export class Gw2ApiService {

    constructor(private readonly httpClient: HttpClient) {
    }

    getAccount(token: string): Observable<Gw2Account> {
        return this.httpClient.get<Gw2TokenInfo>('https://api.guildwars2.com/v2/account', { params: { 'access_token': token } });
    }

    getTokenInfo(token: string): Observable<Gw2TokenInfo> {
        return this.httpClient.get<Gw2TokenInfo>('https://api.guildwars2.com/v2/tokeninfo', { params: { 'access_token': token } });
    }

    getItem(itemId: number): Observable<Gw2Item> {
        return this.httpClient.get<Gw2Item>('https://api.guildwars2.com/v2/items/' + encodeURIComponent(itemId));
    }
}