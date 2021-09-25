import { Injectable } from '@angular/core';
import {Observable, ReplaySubject} from "rxjs";

@Injectable({
  providedIn: 'root'
})
export class ToastService {

  private readonly subject: ReplaySubject<Toast>;

  constructor() {
    this.subject = new ReplaySubject<Toast>();
  }

  show(title: string, message: string, autohide: boolean = true, delay: number = 5000): void {
    this.subject.next({title, message, autohide, delay});
  }

  toasts(): Observable<Toast> {
    return this.subject.asObservable();
  }
}

export interface Toast {
  title: string;
  message: string;
  autohide: boolean;
  delay: number;
}