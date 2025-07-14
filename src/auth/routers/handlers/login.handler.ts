import { NextFunction, Request, Response } from "express";
import { HttpStatus } from "../../../core/types/http-statuses";
import { LoginDto } from "../../dto/login.dto";
import { authService } from "../../domain/auth.service";
import { AuthorizationError } from "../../../core/utils/app-response-errors";
import { LoginSuccessViewModel } from "../../types/LoginSuccessViewModel";
import { SETTINGS } from "../../../core/setting/setting";

export async function authLoginHandler(
  req: Request<{}, {}, LoginDto>,
  res: Response,
  next: NextFunction,
) {
  try {
    const { loginOrEmail, password } = req.body;
    const tokens = await authService.loginUser(loginOrEmail, password);
    if (!tokens) {
      throw new AuthorizationError("Wrong credentials");
    }
    const { accessToken, refreshToken } = tokens;
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      maxAge: SETTINGS.RF_TIME as number,
    });
    res.status(HttpStatus.Ok).send({ accessToken } as LoginSuccessViewModel);
  } catch (e: unknown) {
    next(e);
  }
}
