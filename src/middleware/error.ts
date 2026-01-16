import { Request, Response, NextFunction } from 'express';
import logger from '../utils/logger';

export const errorHandler = (
    err: any,
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const statusCode = err.status || 500;
    const message = err.message || 'An unexpected error occurred in the logic core.';

    logger.error(`[CRITICAL_FAILURE] ${message}`, {
        stack: err.stack,
        path: req.path,
        method: req.method,
        user: (req as any).user?.email
    });

    res.status(statusCode).json({
        status: 'error',
        error_code: statusCode === 500 ? 'INTERNAL_KERNEL_STALL' : 'GATEWAY_ERROR',
        message: message,
        correlation_id: crypto.randomUUID(),
        timestamp: new Date().toISOString()
    });
};
