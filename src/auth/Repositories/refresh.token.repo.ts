import { ObjectId } from "mongodb";
import {refreshTokenCollection} from "../../db/mongodb";
import {RefreshTokenEntity} from "../types/refresh.token.entity";

export const refreshTokenRepository = {
    async save(tokenData: { userId: string; token: string; expiresAt: string }): Promise<ObjectId> {

        const result = await refreshTokenCollection.insertOne({
            userId: tokenData.userId,
            token: tokenData.token,
            expiresAt: tokenData.expiresAt,
        });
        return result.insertedId;
    },

    async findByToken(token: string): Promise<RefreshTokenEntity | null> {
        return await refreshTokenCollection.findOne({ token });
    },

    async deleteByToken(token: string): Promise<boolean> {
        const result = await refreshTokenCollection.deleteOne({ token });
        return result.deletedCount === 1;
    },

    async deleteAllForUser(userId: string): Promise<void> {
        await refreshTokenCollection.deleteMany({ userId });
    }
};
