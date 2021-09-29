import {Component, Input} from '@angular/core';
import {faCopy} from '@fortawesome/free-solid-svg-icons';


@Component({
    selector: 'app-input-copyable',
    template: `
        <ng-template #copyResponse let-message="message">{{message}}</ng-template>
        <div class="input-group">
            <input type="text" class="form-control" [id]="inputId" [disabled]="disabled" [value]="inputValue" [attr.aria-describedby]="ariaDescribedBy" />
            <button class="btn btn-accent-inner" #t="ngbTooltip" [ngbTooltip]="copyResponse" [closeDelay]="1000" triggers="manual" (click)="onCopyClick(t, inputValue)"><fa-icon [icon]="faCopy"></fa-icon></button>
        </div>
    `
})
export class InputCopyableComponent {

    faCopy = faCopy;

    @Input("inputId") inputId!: string;
    @Input("inputValue") inputValue!: string;
    @Input("disabled") disabled = true;
    @Input("aria-describedby") ariaDescribedBy: string | null = null;

    constructor() {
    }

    onCopyClick(tooltip: any, value: string): void {
        navigator.clipboard.writeText(value)
            .then(() => tooltip.open({message: 'Copied!'}))
            .catch(() => tooltip.open({message: 'Copy failed'}));
    }
}