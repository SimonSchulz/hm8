export class RefreshTokenEntity {
    userId: string;
    token: string;
    expiresAt: string;

    constructor(props: {
        userId: string;
        token: string;
        expiresAt: string;
    }) {
        this.userId = props.userId;
        this.token = props.token;
        this.expiresAt = props.expiresAt;
    }

    static createNew(userId: string, token: string, expiresAt: string): RefreshTokenEntity {
        return new RefreshTokenEntity({ userId, token, expiresAt });
    }
}