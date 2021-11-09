import {Component, Input} from '@angular/core';
import {DeleteAbstractModalComponent} from '../../../general/delete-abstract-modal.component';
import {Token} from '../../../common/token.model';

@Component({
    selector: 'app-delete-authorization-modal',
    template: `
        <app-delete-abstract-modal [entityName]="entityName">
            <p class="mb-1">After deleting this Authorization, the Application will still have access to the authorized GW2-Accounts for at most 30 minutes.</p>
            <p class="mb-3">Other Authorizations of this Application will be unaffected by deleting this Authorization.</p>
            <p>Do you really want to delete the Authorization <strong>{{entityName}}</strong>?</p>
        </app-delete-abstract-modal>
    `
})
export class DeleteAuthorizationModalComponent extends DeleteAbstractModalComponent {

}