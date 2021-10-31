import {Component, Input} from '@angular/core';
import {DeleteAbstractModalComponent} from './delete-abstract-modal.component';


@Component({
    selector: 'app-delete-modal',
    template: `
        <app-delete-abstract-modal [entityName]="entityName">
            <p>Do you really want to delete the {{entityType}} <strong>{{entityName}}</strong>?</p>
        </app-delete-abstract-modal>
    `
})
export class DeleteModalComponent extends DeleteAbstractModalComponent {

    @Input('entityType') entityType!: string;
}