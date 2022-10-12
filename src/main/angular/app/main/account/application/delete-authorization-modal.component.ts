import {Component} from '@angular/core';
import {DeleteAbstractModalComponent} from '../../../general/delete-abstract-modal.component';

@Component({
    selector: 'app-delete-authorization-modal',
    template: `
        <app-delete-abstract-modal [entityName]="entityName">
            <p class="mb-1">After deleting this authorization, the application will still have access to the authorized Guild Wars 2 Accounts for at most 30 minutes.</p>
            <p class="mb-3">Other authorizations of this application will be unaffected by deleting this authorization.</p>
            <p>Do you really want to delete the authorization <strong>{{entityName}}</strong>?</p>
        </app-delete-abstract-modal>
    `
})
export class DeleteAuthorizationModalComponent extends DeleteAbstractModalComponent {

}