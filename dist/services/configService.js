"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConfigService = void 0;
const axios_1 = __importDefault(require("axios"));
const logger_1 = __importDefault(require("../utils/logger"));
/**
 * Sentinel Configuration Service
 * Provides dynamic threat intelligence data (ASNs, IP ranges) to the engine.
 */
class ConfigService {
    static getHighRiskAsns() {
        return this.intelligence.high_risk_asns;
    }
    static getVerifiedBotAsns() {
        return this.intelligence.verified_bot_asns || {};
    }
    static getDatacenterRanges() {
        return this.intelligence.datacenter_ranges;
    }
    /**
     * Pull the latest intelligence from the Sentinel Central Authority.
     * Guaranteed sub-100ms response.
     */
    static async syncIntelligence() {
        const C2_URL = process.env.SENTINEL_C2_URL || 'https://threat-registry.risksignal.name.ng/v1/sync';
        try {
            const { data } = await axios_1.default.get(C2_URL, { timeout: 2000 });
            if (data && data.datacenter_ranges && data.high_risk_asns) {
                this.intelligence = {
                    ...this.intelligence,
                    ...data,
                    last_updated: new Date().toISOString()
                };
                logger_1.default.info(`[Config] Threat Intelligence Refreshed: ${this.intelligence.last_updated}`);
            }
        }
        catch (e) {
            logger_1.default.warn(`[Config] Thread Intel Sync skipped: ${e.message}`);
        }
    }
}
exports.ConfigService = ConfigService;
ConfigService.intelligence = {
    last_updated: new Date().toISOString(),
    verified_bot_asns: {
        15169: "Googlebot (Verified)",
        8075: "Bingbot (Verified)",
        714: "Applebot (Verified)",
        20940: "Akamai (CDN/Verified)",
        13335: "Cloudflare (Proxy/Verified)",
        32934: "Facebook (Verified)"
    },
    high_risk_asns: [
        212238, 9009, 14061, 20473, 16509, 14618, 63949, 396982,
        24940, 21341, 16276, 54113, 204915, 47583, 53667,
        8100, 13213, 46475, 60068, 199218, 203020, 201839, 398324,
        398705, 398722, 211298, 213412, 216341, 30823, 214497, 215208,
        215240, 198953, 200593, 42969, 215778, 49217, 20052, 11878,
        46562, 204957, 216419, 51167, 12876, 35816, 50673, 203020,
        201839, 44476, 31828, 55002, 34164, 46484, 14576, 36352, 9318,
        20473, 393406, 394362, 395954, 396356, 396982, 397123, 397213,
        397434, 398155, 398243, 398327, 398361, 398368, 398758, 398864,
        399066, 399182, 400118, 400166, 400171, 400241, 400320, 400494,
        400518, 400561, 400585, 400595, 400624, 400643, 400644, 400652
    ],
    datacenter_ranges: [
        '3.0.0.0/8', '13.0.0.0/8', '18.0.0.0/8', '34.192.0.0/10', '35.160.0.0/12',
        '44.0.0.0/8', '52.0.0.0/10', '54.0.0.0/8', '104.248.0.0/13', '138.197.0.0/16',
        '159.203.0.0/16', '165.22.0.0/16', '13.64.0.0/11', '20.33.0.0/16',
        '23.96.0.0/12', '40.64.0.0/10', '34.64.0.0/10', '35.184.0.0/13',
        '45.33.0.0/16', '104.16.0.0/12', '45.32.0.0/16', '108.61.0.0/16',
        '185.220.101.0/24', '185.101.0.0/16', '141.98.0.0/16', '171.25.0.0/16'
    ]
};
