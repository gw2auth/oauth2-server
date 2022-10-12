import {Component, Input} from '@angular/core';
import {DeleteAbstractModalComponent} from '../../../general/delete-abstract-modal.component';
import {Token} from '../../../common/token.model';

@Component({
    selector: 'app-delete-token-modal',
    template: `
        <app-delete-abstract-modal [entityName]="entityName">
            <div class="mb-3" *ngIf="token.authorizations.length > 0">
                <label [htmlFor]="'applications'" class="form-label">This API Token is currently used by the following applications</label>
                <div class="list-group" [id]="'applications'" [attr.aria-describedby]="'applicationsDescription'">
                    <a *ngFor="let authorization of token.authorizations" class="list-group-item">
                        {{authorization.displayName}}
                    </a>
                </div>
                <div [id]="'applicationsDescription'" class="form-text">
                    Removing this API Token will also remove the listed applications access to this Guild Wars 2 Account.
                    Upon removing this API Token, authorized applications will still have access to this Guild Wars 2 Account for at most 30 minutes.
                </div>
            </div>
            
            <p>Do you really want to delete the API Token <strong>{{token.displayName}}</strong>?</p>
        </app-delete-abstract-modal>
    `
})
export class DeleteTokenModalComponent extends DeleteAbstractModalComponent {

    @Input('token') token!: Token;
}