import {Inject, Injectable} from '@angular/core';
import {BrowserStorageService} from './browser-storage.service';
import {ColorScheme} from './color-scheme.model';
import {ConsentLevel} from './browser-storage.model';
import {combineLatest, Observable, ReplaySubject} from 'rxjs';
import {map} from 'rxjs/operators';
import {WINDOW} from '../app.module';


const STORAGE_CONSENT_LEVEL = ConsentLevel.FUNCTIONALITY;
const STORAGE_KEY = 'PREFERRED_COLOR_SCHEME';


@Injectable({
    providedIn: 'root'
})
export class ColorSchemeService {

    private readonly systemPreferredColorSchemeSubject = new ReplaySubject<ColorScheme.LIGHT | ColorScheme.DARK>(1);

    constructor(@Inject(WINDOW) private readonly window: Window, private readonly browserStorageService: BrowserStorageService) {
        const query = this.window.matchMedia('(prefers-color-scheme: light)');

        this.systemPreferredColorSchemeSubject.next(query.matches ? ColorScheme.LIGHT : ColorScheme.DARK);
        query.onchange = (e) => this.systemPreferredColorSchemeSubject.next(e.matches ? ColorScheme.LIGHT : ColorScheme.DARK);
    }

    setPreferredColorScheme(colorScheme: ColorScheme): void {
        this.browserStorageService.set(STORAGE_CONSENT_LEVEL, STORAGE_KEY, colorScheme);
    }

    getPreferredColorScheme(): Observable<ColorScheme> {
        return this.browserStorageService.get(STORAGE_CONSENT_LEVEL, STORAGE_KEY).pipe(map((value) => {
            if (value == null) {
                return ColorScheme.SYSTEM;
            } else {
                return <ColorScheme> value;
            }
        }));
    }

    getInferredPreferredColorScheme(): Observable<ColorScheme.LIGHT | ColorScheme.DARK> {
        return combineLatest([this.getPreferredColorScheme(), this.systemPreferredColorSchemeSubject.asObservable()]).pipe(map(([chosen, system]) => {
            if (chosen == ColorScheme.SYSTEM) {
                return system;
            }

            return chosen;
        }));
    }
}