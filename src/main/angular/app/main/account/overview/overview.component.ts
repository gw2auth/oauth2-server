import { Component, OnInit } from '@angular/core';
import {AccountSummaryService} from './account-summary.service';
import {AccountSummary} from "./account-summary.model";

@Component({
  selector: 'app-overview',
  templateUrl: './overview.component.html'
})
export class OverviewComponent implements OnInit {

  summary: AccountSummary | null = null;

  constructor(private readonly accountSummaryService: AccountSummaryService) { }

  ngOnInit(): void {
    this.accountSummaryService.getAccountSummary().subscribe((accountSummary) => this.summary = accountSummary);
  }
}
