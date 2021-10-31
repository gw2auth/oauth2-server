import {Component, Input} from '@angular/core';
import {DeleteAbstractModalComponent} from '../../../general/delete-abstract-modal.component';
import {Token} from '../../../common/token.model';

@Component({
    selector: 'app-delete-application-modal',
    template: `
        <app-delete-abstract-modal [entityName]="entityName">
            <p class="mb-3">After deleting this Application, the Application will still have access to the authorized GW2-Accounts for at most 30 minutes.</p>
            <p>Do you really want to delete the Application <strong>{{entityName}}</strong>?</p>
        </app-delete-abstract-modal>
    `
})
export class DeleteApplicationModalComponent extends DeleteAbstractModalComponent {

}