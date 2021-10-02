import {Component, Input} from '@angular/core';
import {Gw2ApiPermission, gw2ApiPermissionDisplayName} from '../common/common.model';
import {faCheck, faBan} from '@fortawesome/free-solid-svg-icons';


@Component({
    selector: 'app-gw2-api-permission-badge',
    template: `
        <span class="badge rounded-pill p-2" [ngClass]="isPresent ? 'bg-success' : 'bg-danger'">
            <fa-icon [icon]="isPresent ? faCheck : faBan"></fa-icon> {{gw2ApiPermissionDisplayName(gw2ApiPermission)}}
        </span>
    `
})
export class Gw2ApiPermissionBadgeComponent {

    faCheck = faCheck;
    faBan = faBan;

    @Input("gw2ApiPermission") gw2ApiPermission!: Gw2ApiPermission;
    @Input("isPresent") isPresent!: boolean;

    constructor() {
    }

    gw2ApiPermissionDisplayName(gw2ApiPermission: Gw2ApiPermission): string {
        return gw2ApiPermissionDisplayName(gw2ApiPermission);
    }
}