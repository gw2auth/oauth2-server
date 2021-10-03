import {Component, Input} from "@angular/core";
import {IconProp} from "@fortawesome/fontawesome-svg-core";

@Component({
    selector: 'app-summary-element',
    template: `
        <div class="card bg-accent">
            <div class="card-header">
                <h3>
                    <fa-icon *ngIf="faIcon != null" [icon]="faIcon"></fa-icon>
                    <span *ngIf="faIcon != null" [textContent]="' '"></span>
                    {{title}}
                </h3>
            </div>
            <div class="card-body">
                <ng-content></ng-content>
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