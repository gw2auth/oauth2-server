import {Component, Input} from '@angular/core';
import {DeleteAbstractModalComponent} from '../../../general/delete-abstract-modal.component';

@Component({
    selector: 'app-delete-application-modal',
    template: `
        <app-delete-abstract-modal [entityName]="entityName">
            <p class="mb-3">After deleting this application, the application will still have access to the authorized Guild Wars 2 Accounts for at most 30 minutes.</p>
            <p>Do you really want to delete the application <strong>{{entityName}}</strong>?</p>
        </app-delete-abstract-modal>
    `
})
export class DeleteApplicationModalComponent extends DeleteAbstractModalComponent {

}