import {Component, Input} from '@angular/core';
import {NgbActiveModal} from '@ng-bootstrap/ng-bootstrap';
import {faRedo, faTimes} from '@fortawesome/free-solid-svg-icons';
import {ClientRegistrationPrivate} from "./client-registration.model";


@Component({
    selector: 'app-regenerate-client-secret-modal',
    template: `
        <div class="modal-header">
            <h5 class="modal-title">Regenerate client secret for {{clientRegistration.displayName}}</h5>
            <button type="button" class="btn btn-sm" (click)="dismiss()" aria-label="Close"><fa-icon [icon]="faTimes"></fa-icon></button>
        </div>
        <div class="modal-body">
            <p>Do you really want to regenerate the client secret for <strong>{{clientRegistration.displayName}}</strong>?</p>
            <p>This action cannot be undone. The client secret will be updated immediately and currently active applications using this client secret will no longer work until you update their configuration accordingly!</p>
            <form>
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" value="" [id]="'regenerate-client-secret-confirm'" [(ngModel)]="confirmed" name="confirmed" />
                    <label [htmlFor]="'regenerate-client-secret-confirm'">Yes, regenerate client secret</label>
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-accent-inner" (click)="dismiss()"><fa-icon [icon]="faTimes"></fa-icon> Cancel</button>
            <button type="button" class="btn btn-danger" [disabled]="!confirmed" (click)="close()"><fa-icon [icon]="faRedo"></fa-icon> Regenerate</button>
        </div>
    `
})
export class RegenerateClientSecretModalComponent {

    faRedo = faRedo;
    faTimes = faTimes;

    @Input('clientRegistration') clientRegistration!: ClientRegistrationPrivate;

    confirmed = false;

    constructor(private readonly activeModal: NgbActiveModal) {}

    dismiss(): void {
        this.activeModal.dismiss(false);
    }

    close(): void {
        this.activeModal.close(this.confirmed);
    }
}