import { Component, OnInit } from '@angular/core';
import {Toast, ToastService} from './toast.service';
import {faTimes} from '@fortawesome/free-solid-svg-icons';


class InternalToast {

  currentAutohide: boolean;

  constructor(readonly parent: Toast) {
    this.currentAutohide = parent.autohide;
  }
}

@Component({
  selector: 'app-toast',
  templateUrl: './toast.component.html',
  styleUrls: ['./toast.component.scss']
})
export class ToastComponent implements OnInit {

  faTimes = faTimes;

  toasts: InternalToast[] = [];

  constructor(private readonly toastService: ToastService) {}

  ngOnInit(): void {
    this.toastService.toasts().subscribe((toast) => this.toasts.push(new InternalToast(toast)));
  }
}
