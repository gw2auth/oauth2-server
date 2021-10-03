import {Component, Input} from "@angular/core";
import {IconProp} from "@fortawesome/fontawesome-svg-core";

@Component({
    selector: 'app-summary-element',
    template: `
        <div class="card bg-accent h-100">
            <div class="card-header text-center">
                <h3>
                    <fa-icon *ngIf="faIcon != null" [icon]="faIcon"></fa-icon>
                    <span *ngIf="faIcon != null" [textContent]="' '"></span>
                    {{title}}
                </h3>
            </div>
            <div class="card-body d-flex align-items-center">
                <div class="w-100 text-center">
                    <ng-content></ng-content>
                </div>
            </div>
        </div>
    `
})
export class SummaryElementComponent {

    @Input("title") title = '';
    @Input("faIcon") faIcon: IconProp | null = null;

    constructor() {
    }
}