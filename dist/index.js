"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const helmet_1 = __importDefault(require("helmet"));
const morgan_1 = __importDefault(require("morgan"));
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const dotenv_1 = __importDefault(require("dotenv"));
const path_1 = __importDefault(require("path"));
const logger_1 = __importDefault(require("./utils/logger"));
const intelRoutes_1 = __importDefault(require("./routes/intelRoutes"));
const configService_1 = require("./services/configService");
const telemetryService_1 = require("./services/telemetryService");
const authRoutes_1 = __importDefault(require("./routes/authRoutes"));
const payRoutes_1 = __importDefault(require("./routes/payRoutes"));
const error_1 = require("./middleware/error");
const visitor_1 = require("./middleware/visitor");
dotenv_1.default.config();
const app = (0, express_1.default)();
const PORT = process.env.PORT || 3001;
// Trust Proxy: set to false for local development to avoid rate-limit validation errors
app.set('trust proxy', false);
// 1. Security & Middleware
app.use((0, helmet_1.default)({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://*.supabase.co"],
            scriptSrcElem: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://*.supabase.co"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            styleSrcElem: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https://*"],
            connectSrc: ["'self'", "https://ahwkraeuotptvwvutbng.supabase.co", "https://*.supabase.co", "https://*.supabase.net", "https://cdn.jsdelivr.net", "https://nowpayments.io"],
            frameSrc: ["'self'", "https://*.supabase.co", "https://nowpayments.io"],
        },
    },
    crossOriginResourcePolicy: { policy: "cross-origin" },
    crossOriginEmbedderPolicy: false
}));
app.use((0, cors_1.default)());
app.use(express_1.default.json());
app.use((0, morgan_1.default)('combined', {
    stream: { write: (message) => logger_1.default.info(message.trim()) }
}));
// 2. Visitor Tracking (Secretly monitoring growth)
app.use(visitor_1.visitorTracker);
// 3. Global Rate Limiting (Enterprise Grade)
const limiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 600, // Limit each IP to 100 requests per window
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests from this IP, please try again later.' }
});
app.use(limiter);
// 3. Serve Landing Page (Static Files)
app.use(express_1.default.static(path_1.default.join(__dirname, '..', 'landing-page'), {
    setHeaders: (res) => {
        res.set('Cross-Origin-Resource-Policy', 'cross-origin');
    }
}));
// Root route serves landing page
app.get('/', (req, res) => {
    res.sendFile(path_1.default.join(__dirname, '..', 'landing-page', 'index.html'));
});
// 4. Health Check
app.get('/health', (req, res) => {
    res.json({ status: 'UP', service: 'Sentinel-Engine', version: '1.0.1' });
});
// 5. API Routes
app.use('/v1', intelRoutes_1.default);
// 6. Auth & Payment Routes
app.use('/auth', authRoutes_1.default);
app.use('/api', authRoutes_1.default);
app.use('/v1/pay', payRoutes_1.default);
// 7. 404 & Error Handling
app.use((req, res, next) => {
    res.status(404).json({ error: 'Endpoint destination unreachable.' });
});
app.use(error_1.errorHandler);
app.listen(PORT, async () => {
    logger_1.default.info(`🚀 Sentinel Engine ACTIVE on Port ${PORT}`);
    logger_1.default.info(`Environment: ${process.env.NODE_ENV}`);
    // Sync Intelligence on Startup
    logger_1.default.info('Initializing Dynamic Threat Matrix...');
    await configService_1.ConfigService.syncIntelligence();
    // Periodic Sync (Every 6 hours)
    setInterval(() => {
        configService_1.ConfigService.syncIntelligence();
    }, 1000 * 60 * 60 * 6);
    // Initialize the DB Auto-Cleanup Job (Prevents Supabase Free Tier crash)
    telemetryService_1.TelemetryService.startRetentionCron();
});
