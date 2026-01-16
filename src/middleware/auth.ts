import { Request, Response, NextFunction } from 'express';
import { supabase } from '../config/supabase';
import logger from '../utils/logger';

declare global {
    namespace Express {
        interface User {
            id: string | number;
            email?: string;
            usage_count?: number;
            max_usage?: number;
            github_id?: string;
            github_login?: string;
            github_name?: string;
            avatar_url?: string;
            created_at?: Date;
        }
    }
}

export interface AuthRequest extends Request {
    // Relying on global Express.User augmentation
}

export const authMiddleware = async (req: AuthRequest, res: Response, next: NextFunction) => {
    let apiKey = req.headers['x-api-key'] as string;
    const authHeader = req.headers['authorization'];

    // Support Bearer Token (Site Keys)
    if (!apiKey && authHeader && authHeader.startsWith('Bearer ')) {
        apiKey = authHeader.split(' ')[1];
    }

    if (!apiKey) {
        return res.status(401).json({ error: 'Missing security credentials.' });
    }

    try {
        const { data: authData, error: authError } = await supabase
            .from('api_access')
            .select('*')
            .eq('api_key', apiKey)
            .single();

        if (authError || !authData) {
            logger.warn(`Invalid access attempt: ${apiKey.substring(0, 8)}...`);
            return res.status(403).json({ error: 'Invalid security key.' });
        }

        req.user = {
            id: authData.id,
            email: authData.email,
            usage_count: authData.usage_count,
            max_usage: authData.max_usage,
        };

        // Cache the raw record ID for the quota middleware
        (req as any).apiRecordId = authData.id;

        next();
    } catch (err: any) {
        logger.error('Auth middleware exception', err);
        return res.status(500).json({ error: 'Internal server error during authentication.' });
    }
};

// Middleware to gated usage for analysis endpoints
export const quotaMiddleware = async (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user || !(req as any).apiRecordId) {
        return res.status(401).json({ error: 'Authentication required for this operation.' });
    }

    if (req.user.usage_count! >= req.user.max_usage!) {
        return res.status(402).json({ error: 'Quota exceeded. Contact support for higher limits.' });
    }

    try {
        await supabase
            .from('api_access')
            .update({ usage_count: req.user.usage_count! + 1 })
            .eq('id', (req as any).apiRecordId);

        next();
    } catch (err) {
        logger.error('Quota update failed', err);
        next(); // Still proceed
    }
};
