import { Request, Response, NextFunction } from "express";
import { HttpStatus } from "../../../core/types/http-statuses";
import { refreshTokenRepository } from "../../Repositories/refresh.token.repo";
import { AuthorizationError } from "../../../core/utils/app-response-errors";

export async function logoutHandler(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const refreshToken: string = req.cookies.refreshToken;

    if (!refreshToken) {
      throw new AuthorizationError("Refresh token provided");
    }

    const tokenInDb = await refreshTokenRepository.findByToken(refreshToken);

    if (!tokenInDb) {
      throw new AuthorizationError("Refresh token provided");
    }

    await refreshTokenRepository.deleteByToken(refreshToken);

    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: true,
    });

    res.sendStatus(HttpStatus.NoContent);
  } catch (error) {
    next(error);
  }
}
