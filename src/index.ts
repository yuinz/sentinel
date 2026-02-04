import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import path from 'path';
import logger from './utils/logger';
import intelRoutes from './routes/intelRoutes';
import authRoutes from './routes/authRoutes';
import payRoutes from './routes/payRoutes';
import { errorHandler } from './middleware/error';
import { visitorTracker } from './middleware/visitor';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Trust Proxy: set to false for local development to avoid rate-limit validation errors
app.set('trust proxy', false);

// 1. Security & Middleware
app.use(helmet({
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
app.use(cors());
app.use(express.json());
app.use(morgan('combined', {
    stream: { write: (message) => logger.info(message.trim()) }
}));

// 2. Visitor Tracking (Secretly monitoring growth)
app.use(visitorTracker);

// 3. Global Rate Limiting (Enterprise Grade)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 600, // Limit each IP to 100 requests per window
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests from this IP, please try again later.' }
});
app.use(limiter);

// 3. Serve Landing Page (Static Files)
app.use(express.static(path.join(__dirname, '..', 'landing-page'), {
    setHeaders: (res) => {
        res.set('Cross-Origin-Resource-Policy', 'cross-origin');
    }
}));

// Root route serves landing page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'landing-page', 'index.html'));
});

// 4. Health Check
app.get('/health', (req, res) => {
    res.json({ status: 'UP', service: 'Sentinel-Engine', version: '1.0.1' });
});

// 5. API Routes
app.use('/v1', intelRoutes);

// 6. Auth & Payment Routes
app.use('/auth', authRoutes);
app.use('/api', authRoutes);
app.use('/v1/pay', payRoutes);

// 7. 404 & Error Handling
app.use((req, res, next) => {
    res.status(404).json({ error: 'Endpoint destination unreachable.' });
});

app.use(errorHandler as any);

app.listen(PORT, () => {
    logger.info(`🚀 Sentinel Engine ACTIVE on Port ${PORT}`);
    logger.info(`Environment: ${process.env.NODE_ENV}`);
});
