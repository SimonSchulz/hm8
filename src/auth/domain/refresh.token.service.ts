import { refreshTokenRepository } from "../Repositories/refresh.token.repo";
import { jwtService } from "./jwt.service";
import { AuthorizationError } from "../../core/utils/app-response-errors";

export const refreshService = {
  async refreshToken(oldRefreshToken: string) {
    if (!oldRefreshToken) {
      throw new AuthorizationError("No refresh token provided");
    }

    const isBlacklisted =
      await refreshTokenRepository.isTokenInvalidated(oldRefreshToken);
    if (isBlacklisted) {
      throw new AuthorizationError("Refresh token not found or already used");
    }

    const payload = await jwtService.verifyRefreshToken(oldRefreshToken);
    if (!payload) {
      throw new AuthorizationError("Invalid or expired refresh token");
    }

    const userId = payload.userId;
    const oldExpiresAt = jwtService.getTokenExpiration(oldRefreshToken);
    if (!oldExpiresAt) {
      throw new Error("Can't extract expiration from old refresh token");
    }

    await refreshTokenRepository.saveInvalidToken({
      userId,
      token: oldRefreshToken,
      expiresAt: oldExpiresAt,
    });

    const newAccessToken = await jwtService.createAccessToken(userId);
    const newRefreshToken = await jwtService.createRefreshToken(userId);
    const newExpiresAt = jwtService.getTokenExpiration(newRefreshToken);

    if (!newExpiresAt) {
      throw new Error("Can't extract expiration from new refresh token");
    }

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  },
};
