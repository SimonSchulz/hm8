import { refreshTokenRepository } from "../Repositories/refresh.token.repo";
import { jwtService } from "./jwt.service";
import { AuthorizationError } from "../../core/utils/app-response-errors";

export const refreshService = {
  async refreshToken(oldRefreshToken: string) {
    if (!oldRefreshToken) {
      throw new AuthorizationError("No refresh token provided");
    }
    const tokenRecord =
      await refreshTokenRepository.findByToken(oldRefreshToken);
    if (!tokenRecord) {
      throw new AuthorizationError("Refresh token not found or already used");
    }

    const payload = await jwtService.verifyRefreshToken(oldRefreshToken);
    if (!payload) {
      throw new AuthorizationError("Invalid or expired refresh token");
    }

    const userId = payload.userId;

    await refreshTokenRepository.deleteByToken(oldRefreshToken);

    const newAccessToken = await jwtService.createAccessToken(userId);
    const newRefreshToken = await jwtService.createRefreshToken(userId);
    const expiresAt = jwtService.getTokenExpiration(newRefreshToken);

    if (!expiresAt) {
      throw new Error("Can't extract expiration from refresh token");
    }

    await refreshTokenRepository.save({
      userId,
      token: newRefreshToken,
      expiresAt,
    });

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  },
};
