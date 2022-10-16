export interface AccountLog {
    timestamp: Date;
    message: string;
    fields: {[k: string]: any}
}

export interface AccountLogs {
    page: number;
    nextPage: number;
    logs: AccountLog[];
}