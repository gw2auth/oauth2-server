import { Component, OnInit } from '@angular/core';
import {ApplicationSummary} from './application-summary.model';
import {ApplicationSummaryService} from "./application-summary.service";

@Component({
  selector: 'app-main-home',
  templateUrl: './home.component.html'
})
export class HomeComponent implements OnInit {

  summary: ApplicationSummary | null = null;

  constructor(private readonly applicationSummaryService: ApplicationSummaryService) {

  }

  ngOnInit(): void {
    this.applicationSummaryService.getApplicationSummary().subscribe((applicationSummary) => this.summary = applicationSummary);
  }
}
