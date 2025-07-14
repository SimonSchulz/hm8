import { Request, Response, NextFunction } from "express";
import { HttpStatus } from "../../../core/types/http-statuses";
import { AuthorizationError } from "../../../core/utils/app-response-errors";
import { SETTINGS } from "../../../core/setting/setting";
import { LoginSuccessViewModel } from "../../types/LoginSuccessViewModel";
import { refreshTokenRepository } from "../../Repositories/refresh.token.repo";
import { jwtService } from "../../domain/jwt.service";

export async function refreshTokenHandler(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const oldRefreshToken = req.cookies.refreshToken;

    if (!oldRefreshToken) {
      throw new AuthorizationError("No refresh token provided");
    }

    const tokenRecord =
      await refreshTokenRepository.findByToken(oldRefreshToken);
    if (!tokenRecord) {
      throw new AuthorizationError("Refresh token not found or already used");
    }

    const payload = await jwtService.verifyToken(oldRefreshToken);
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

    res
      .cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure: true,
        maxAge: Number(SETTINGS.RF_TIME),
      })
      .status(HttpStatus.Ok)
      .send({ accessToken: newAccessToken } as LoginSuccessViewModel);
  } catch (error) {
    next(error);
  }
}
