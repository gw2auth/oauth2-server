import {Inject, Injectable, InjectionToken} from '@angular/core';
import {Observable, ReplaySubject, Subject} from 'rxjs';
import {ConsentLevel} from './browser-storage.model';


class StorageNode {

    private readonly subject: Subject<string | null>;
    private value: string | null = null;
    isInitial = true;
    isPersistent = false;

    constructor(readonly consentLevel: ConsentLevel, readonly key: string) {
        this.subject = new ReplaySubject<string | null>(1);
    }

    next(value: string | null): void {
        this.value = value;
        this.subject.next(value);
    }

    asObservable(): Observable<string | null> {
        return this.subject.asObservable();
    }

    getValue(): string | null {
        return this.value;
    }
}

// this is mainly to avoid clashing with other applications during local development
const STORAGE_PREFIX = 'GW2AUTH:';

export const BROWSER_STORAGE = new InjectionToken<Storage>('Browser Storage', {
    providedIn: 'root',
    factory: () => localStorage
});


@Injectable({
    providedIn: 'root'
})
export class BrowserStorageService {

    private readonly storageNodeMap = new Map<string, StorageNode>();
    private readonly allowedConsentLevels = new Set<ConsentLevel>();

    constructor(@Inject(BROWSER_STORAGE) private readonly storage: Storage) {
        this.allowedConsentLevels.add(ConsentLevel.STRICTLY_NECESSARY);
    }

    private getOrCreateNode(consentLevel: ConsentLevel, key: string): StorageNode {
        let node = this.storageNodeMap.get(key);
        if (node == undefined) {
            node = new StorageNode(consentLevel, key);
            this.storageNodeMap.set(key, node);

            // every node should have a value set so the subscribers fire once right at the start
            node.next(null);
        }

        if (node.consentLevel != consentLevel) {
            throw new Error(`ConsentLevels for node ${key} do not match: ${node.consentLevel} and ${consentLevel}`);
        }

        return node;
    }

    setAllowedConsentLevels(consentLevels: ConsentLevel[]): void {
        this.allowedConsentLevels.clear();
        this.allowedConsentLevels.add(ConsentLevel.STRICTLY_NECESSARY);

        for (let consentLevel of consentLevels) {
            this.allowedConsentLevels.add(consentLevel);
        }

        this.storageNodeMap.forEach((node, key) => {
            if (this.allowedConsentLevels.has(node.consentLevel)) {
                if (!node.isPersistent) {
                    let value = node.getValue();

                    if (value == null) {
                        value = this.storage.getItem(STORAGE_PREFIX + node.key);

                        if (value != null) {
                            node.isPersistent = true;
                            node.next(value);
                        }
                    } else {
                        this.storage.setItem(STORAGE_PREFIX + node.key, value);
                        node.isPersistent = true;
                    }
                }
            } else {
                if (node.isPersistent) {
                    this.storage.removeItem(STORAGE_PREFIX + node.key);
                    node.isPersistent = false;
                }
            }
        });
    }

    set(consentLevel: ConsentLevel, key: string, value: string): void {
        const node = this.getOrCreateNode(consentLevel, key);
        node.isInitial = false;

        if (this.allowedConsentLevels.has(node.consentLevel)) {
            this.storage.setItem(STORAGE_PREFIX + node.key, value);
            node.isPersistent = true;
        }

        node.next(value);
    }

    get(consentLevel: ConsentLevel, key: string): Observable<string | null> {
        const node = this.getOrCreateNode(consentLevel, key);

        if (node.isInitial) {
            node.isInitial = false;

            if (this.allowedConsentLevels.has(node.consentLevel)) {
                const value = this.storage.getItem(STORAGE_PREFIX + node.key);
                if (value != null) {
                    node.isPersistent = true;
                    node.next(value);
                }
            }
        }

        return node.asObservable();
    }

    remove(key: string): void {
        this.storage.removeItem(STORAGE_PREFIX + key);

        const node = this.storageNodeMap.get(key);

        if (node != undefined) {
            node.next(null);
            node.isPersistent = false;
        }
    }
}