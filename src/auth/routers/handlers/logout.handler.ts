import { Request, Response, NextFunction } from "express";
import { HttpStatus } from "../../../core/types/http-statuses";
import { refreshTokenRepository } from "../../Repositories/refresh.token.repo";
import { AuthorizationError } from "../../../core/utils/app-response-errors";
import { jwtService } from "../../domain/jwt.service";

export async function logoutHandler(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const refreshToken: string = req.cookies.refreshToken;

    if (!refreshToken) {
      throw new AuthorizationError("No refresh token provided");
    }

    const payload = await jwtService.verifyRefreshToken(refreshToken);
    if (!payload) {
      throw new AuthorizationError("Invalid refresh token provided");
    }

    const expiresAt = jwtService.getTokenExpiration(refreshToken);
    if (!expiresAt) {
      throw new Error("Can't extract expiration from refresh token");
    }

    await refreshTokenRepository.saveInvalidToken({
      userId: payload.userId,
      token: refreshToken,
      expiresAt,
    });

    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: true,
    });

    res.sendStatus(HttpStatus.NoContent);
  } catch (error) {
    next(error);
  }
}
