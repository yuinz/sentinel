"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.errorHandler = void 0;
const logger_1 = __importDefault(require("../utils/logger"));
const errorHandler = (err, req, res, next) => {
    const statusCode = err.status || 500;
    const message = err.message || 'An unexpected error occurred in the logic core.';
    logger_1.default.error(`[CRITICAL_FAILURE] ${message}`, {
        stack: err.stack,
        path: req.path,
        method: req.method,
        user: req.user?.email
    });
    res.status(statusCode).json({
        status: 'error',
        error_code: statusCode === 500 ? 'INTERNAL_KERNEL_STALL' : 'GATEWAY_ERROR',
        message: message,
        correlation_id: crypto.randomUUID(),
        timestamp: new Date().toISOString()
    });
};
exports.errorHandler = errorHandler;
