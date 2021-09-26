import {Component, Input} from '@angular/core';
import {IconProp} from '@fortawesome/fontawesome-svg-core';


@Component({
    selector: 'app-button-loadable',
    template: `
        <button  [attr.type]="type" class="btn" [ngClass]="class" [disabled]="disabled || loading">
            <fa-icon *ngIf="faIcon != null && !loading" [icon]="faIcon"></fa-icon>
            <span *ngIf="loading" class="spinner-border spinner-border-sm" role="status"></span>
            <span *ngIf="loading || faIcon != null" [textContent]="' '"></span><ng-content></ng-content>
        </button>
    `
})
export class ButtonLoadableComponent {

    @Input("disabled") disabled!: boolean;
    @Input("loading") loading!: boolean;
    @Input("class") class: string | string[] | Set<string> | { [klass: string]: any; } = [];
    @Input("type") type = 'button';
    @Input("faIcon") faIcon: IconProp | null = null;

    constructor() {
    }
}