import { Request, Response, NextFunction } from "express";
import { HttpStatus } from "../../../core/types/http-statuses";
import { refreshTokenRepository } from "../../Repositories/refresh.token.repo";

export async function logoutHandler(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const refreshToken: string = req.cookies.refreshToken;

    if (refreshToken) {
      await refreshTokenRepository.deleteByToken(refreshToken);
    }

    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: true,
    });

    res.sendStatus(HttpStatus.NoContent);
  } catch (error) {
    next(error);
  }
}
