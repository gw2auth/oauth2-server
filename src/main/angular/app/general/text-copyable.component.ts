import {Component, ElementRef, ViewChild} from '@angular/core';
import {faCopy} from '@fortawesome/free-solid-svg-icons';


@Component({
    selector: 'app-text-copyable',
    template: `
        <ng-template #copyResponse let-message="message">{{message}}</ng-template>
        <span #t="ngbTooltip" [ngbTooltip]="copyResponse" [closeDelay]="1000" triggers="manual" style="cursor: pointer;" (click)="onCopyClick(t)">
            <span #content><ng-content></ng-content></span>&nbsp;<fa-icon [icon]="faCopy"></fa-icon>
        </span>
    `
})
export class TextCopyableComponent {

    faCopy = faCopy;

    @ViewChild('content') content!: ElementRef<HTMLElement>;

    constructor() {
    }

    onCopyClick(tooltip: any): void {
        let text = this.content?.nativeElement?.textContent;
        if (text == null) {
            text = '';
        }

        navigator.clipboard.writeText(text)
            .then(() => tooltip.open({message: 'Copied!'}))
            .catch(() => tooltip.open({message: 'Copy failed'}));
    }
}