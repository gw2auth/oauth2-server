import {Component, OnInit} from '@angular/core';
import {VerificationService} from './verification.service';
import {
    ApiTokenNameMessage,
    CharacterNameMessage,
    TpBuyOrderMessage,
    VerificationChallengeStart
} from './verification.model';
import {Observable, of} from 'rxjs';
import {catchError, map} from 'rxjs/operators';
import {Gw2ApiService} from '../../../common/gw2-api.service';
import {Router} from '@angular/router';


@Component({
    selector: 'app-verification-setup-instructions',
    templateUrl: './verification-setup-instructions.component.html'
})
export class VerificationSetupInstructionsComponent implements OnInit {

    startedChallenge: VerificationChallengeStart | null = null;
    tpBuyOrderMessageObservableCache = new Map<any, Observable<{ gold: number, silver: number, copper: number, name: string, icon: string}>>();

    constructor(private readonly verificationService: VerificationService,
                private readonly gw2ApiService: Gw2ApiService,
                private readonly router: Router) {
    }

    ngOnInit(): void {
        this.verificationService.getBootstrap().subscribe((bootstrap) => {
            if (bootstrap.startedChallenge != null) {
                const challenges = bootstrap.availableChallenges.map((v) => this.verificationService.challengeFromResponse(v));
                this.startedChallenge = this.verificationService.challengeStartFromResponse(bootstrap.startedChallenge, challenges);
            }
        });
    }

    asApiTokenMessage(v: VerificationChallengeStart): string {
        return (<ApiTokenNameMessage><unknown>v.message).apiTokenName;
    }

    asTpBuyOrderMessage(v: VerificationChallengeStart): Observable<{ gold: number, silver: number, copper: number, name: string, icon: string}> {
        let observable = this.tpBuyOrderMessageObservableCache.get(v.message);

        if (observable == undefined) {
            const tpBuyOrderMessage = <TpBuyOrderMessage><unknown>v.message;

            observable = this.gw2ApiService.getItem(tpBuyOrderMessage.gw2ItemId).pipe(
                map((gw2Item) => {
                    let coins = tpBuyOrderMessage.buyOrderCoins;

                    const copper = coins % 100;
                    coins = (coins - copper) / 100;

                    const silver = coins % 100;
                    coins = (coins - silver) / 100;

                    const icon = gw2Item.icon
                        .replace('https://render.guildwars2.com/file/', 'https://icons-gw2.darthmaim-cdn.com/')
                        .replace('.png', '-64px.png');

                    return {gold: coins, silver: silver, copper: copper, name: gw2Item.name, icon: icon};
                }),
                catchError((e) => {
                    return of({gold: 0, silver: 0, copper: 0, name: '', icon: ''});
                })
            );

            this.tpBuyOrderMessageObservableCache.set(v.message, observable);
        }

        return observable;
    }

    asCharacterMessage(v: VerificationChallengeStart): string {
        return (<CharacterNameMessage><unknown>v.message).characterName;
    }

    onChallengeDoneClick(): void {
        this.router.navigate(['/', 'account', 'verification', 'setup', 'submit']);
    }
}