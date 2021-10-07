export enum Type {
    ADD_TOKEN,
    UPDATE_TOKEN,
    DELETE_TOKEN,
    AUTHENTICATION
}

export class MessageEventData<T> {

    constructor(readonly type: Type, readonly payload: T) {
    }
}