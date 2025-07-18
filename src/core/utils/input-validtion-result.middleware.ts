import {
    FieldValidationError,
    ValidationError,
    validationResult,
} from 'express-validator';
import { NextFunction, Request, Response } from 'express';
import {ValidationErrorType} from "../types/validationErrorType";
import {HttpStatus} from "../types/http-statuses";


const formatErrors = (error: ValidationError): ValidationErrorType => {
    const expressError = error as unknown as FieldValidationError;
    return {
        field: expressError.path,
        message: expressError.msg,
    };
};

export const inputValidationResultMiddleware = (
    req: Request,
    res: Response,
    next: NextFunction,
) => {
    const errors = validationResult(req)
        .formatWith(formatErrors)
        .array({ onlyFirstError: true });

    if (errors.length > 0) {
        res.status(HttpStatus.BadRequest).json({ errorsMessages: errors });
        return;
    }
    next();
};
