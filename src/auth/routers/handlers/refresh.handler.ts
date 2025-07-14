import { Request, Response, NextFunction } from "express";
import { HttpStatus } from "../../../core/types/http-statuses";
import { LoginSuccessViewModel } from "../../types/LoginSuccessViewModel";
import { SETTINGS } from "../../../core/setting/setting";
import { refreshService } from "../../domain/refresh.token.service";

export async function refreshTokenHandler(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const oldRefreshToken = req.cookies.refreshToken;
    const tokens = await refreshService.refreshToken(oldRefreshToken);

    res
      .cookie("refreshToken", tokens.refreshToken, {
        httpOnly: true,
        secure: true,
        maxAge: Number(SETTINGS.RF_TIME),
      })
      .status(HttpStatus.Ok)
      .send({ accessToken: tokens.accessToken } as LoginSuccessViewModel);
  } catch (error) {
    next(error);
  }
}
