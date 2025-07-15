import { ObjectId } from "mongodb";
import { refreshTokenCollection } from "../../db/mongodb";
import { RefreshTokenEntity } from "../types/refresh.token.entity";

export const refreshTokenRepository = {
  async saveInvalidToken(tokenData: RefreshTokenEntity): Promise<ObjectId> {
    const result = await refreshTokenCollection.insertOne({
      userId: tokenData.userId,
      token: tokenData.token,
      expiresAt: tokenData.expiresAt,
    });
    return result.insertedId;
  },

  async isTokenInvalidated(token: string): Promise<boolean> {
    const found = await refreshTokenCollection.findOne({ token });
    return !!found;
  },
};
