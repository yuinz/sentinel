"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DossierService = void 0;
const axios_1 = __importDefault(require("axios"));
const supabase_1 = require("../config/supabase");
const intelService_1 = require("./intelService");
const IntelServiceV2_1 = require("./v2/IntelServiceV2");
const TenantService_1 = require("./v2/TenantService");
const configService_1 = require("./configService");
const cache_1 = require("../utils/cache");
const logger_1 = __importDefault(require("../utils/logger"));
function pick(obj) {
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
        if (v === undefined || v === null || v === '' || v === 'Unknown' || v === 'UNKNOWN')
            continue;
        out[k] = v;
    }
    return out;
}
async function fetchIpWho(ip) {
    try {
        const { data } = await axios_1.default.get(`https://ipwho.is/${ip}`, { timeout: 2500 });
        return data?.success ? data : null;
    }
    catch (e) {
        logger_1.default.warn(`[Dossier] ipwho.is failed: ${e.message}`);
        return null;
    }
}
async function fetchIpApiIs(ip) {
    try {
        const { data } = await axios_1.default.get(`https://api.ipapi.is/?q=${ip}`, { timeout: 2500 });
        return data?.ip ? data : null;
    }
    catch (e) {
        logger_1.default.warn(`[Dossier] ipapi.is failed: ${e.message}`);
        return null;
    }
}
async function readVpnCache(ip) {
    try {
        if (cache_1.redisClient) {
            const v = await cache_1.redisClient.get(`v2:async:${ip}:vpn`);
            if (v === null)
                return null;
            return v === 'true';
        }
        const v = cache_1.intelCache.get(`v2:async:${ip}:vpn`);
        if (v === undefined)
            return null;
        return v === 'true';
    }
    catch {
        return null;
    }
}
async function historyForIp(userId, ip, limit = 20) {
    const { data: keys } = await supabase_1.supabase
        .from('api_access')
        .select('id, api_key')
        .eq('user_id', userId);
    if (!keys?.length)
        return { history: [], apiKey: '' };
    const keyIds = keys.map(k => k.id);
    const { data: logs } = await supabase_1.supabase
        .from('telemetry')
        .select('verdict, trust_score, latency_ms, profile, reason, bwt_verified, created_at, target')
        .in('api_access_id', keyIds)
        .eq('target', ip)
        .order('created_at', { ascending: false })
        .limit(limit);
    return {
        history: (logs || []).map(l => ({
            verdict: l.verdict,
            score: l.trust_score,
            latency_ms: l.latency_ms,
            profile: l.profile,
            reason: l.reason,
            bwt_verified: !!l.bwt_verified,
            time: l.created_at
        })),
        apiKey: keys[0].api_key
    };
}
/**
 * Live IP dossier: parallel enrich + tenant evaluate + history.
 * Only returns fields that resolved — no placeholders.
 */
class DossierService {
    static async build(userId, rawIp, observed) {
        const target = intelService_1.IntelService.normalizeTarget(rawIp);
        const sources = [];
        const [ipwho, ipapi, vpnCached, hist, matrix, velocity] = await Promise.all([
            fetchIpWho(target),
            fetchIpApiIs(target),
            readVpnCache(target),
            historyForIp(userId, target),
            Promise.resolve(intelService_1.IntelService.checkLocalAsnMatrix(target)),
            cache_1.SharedCache.peekVelocity(target),
        ]);
        if (ipwho)
            sources.push('ipwho.is');
        if (ipapi)
            sources.push('ipapi.is');
        if (vpnCached !== null)
            sources.push('sentinel.vpn_cache');
        if (matrix?.risk)
            sources.push('sentinel.asn_matrix');
        // Trust card (uses cache / providers internally)
        const trustCard = await intelService_1.IntelService.fetchTrustCard(target);
        if (trustCard)
            sources.push('sentinel.trust_card');
        // Live evaluate under tenant policy
        let evaluation = null;
        let policyMode;
        if (hist.apiKey) {
            const policy = await TenantService_1.TenantService.getPolicy(hist.apiKey);
            policyMode = policy.mode;
            evaluation = await IntelServiceV2_1.IntelServiceV2.evaluate(target, policy, undefined, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
            sources.push('sentinel.v2.evaluate');
        }
        const asnFromWho = ipwho?.connection?.asn ?? ipwho?.asn;
        const asnFromApi = ipapi?.asn?.asn;
        const asnNum = parseInt(String(asnFromApi ?? asnFromWho ?? trustCard?.network?.asn ?? 0), 10) || null;
        const verifiedBot = asnNum ? configService_1.ConfigService.getVerifiedBotAsns()[asnNum] : undefined;
        const highRiskAsn = asnNum ? configService_1.ConfigService.getHighRiskAsns().includes(asnNum) : false;
        const network = pick({
            asn: asnNum ? `AS${asnNum}` : null,
            as_name: ipapi?.asn?.org || ipwho?.connection?.org || trustCard?.network?.provider || null,
            isp: ipapi?.asn?.isp || ipwho?.connection?.isp || trustCard?.network?.system || null,
            route: ipapi?.asn?.route || ipwho?.connection?.route || null,
            domain: ipapi?.asn?.domain || ipwho?.connection?.domain || null,
            type: trustCard?.network?.node_type
                || (ipapi?.is_datacenter || ipwho?.connection?.type === 'hosting' ? 'Infrastructure' : null)
                || ipwho?.type
                || null,
            protocol: target.includes(':') ? 'IPv6' : 'IPv4'
        });
        const geo = pick({
            country: ipwho?.country || ipapi?.location?.country || trustCard?.geo?.location || null,
            country_code: ipwho?.country_code || ipapi?.location?.country_code || ipapi?.location?.countryCode || trustCard?.network?.zone || null,
            region: ipwho?.region || ipapi?.location?.state || null,
            city: ipwho?.city || ipapi?.location?.city || trustCard?.geo?.city || null,
            postal: ipwho?.postal || ipapi?.location?.zip || null,
            latitude: ipwho?.latitude ?? ipapi?.location?.latitude ?? null,
            longitude: ipwho?.longitude ?? ipapi?.location?.longitude ?? null,
            timezone: ipwho?.timezone?.id || ipapi?.location?.timezone || null,
            utc_offset: ipwho?.timezone?.utc || null
        });
        const security = pick({
            is_vpn: ipapi?.is_vpn ?? ipwho?.security?.vpn ?? (vpnCached === true ? true : null),
            is_proxy: ipapi?.is_proxy ?? ipwho?.security?.proxy ?? null,
            is_tor: ipapi?.is_tor ?? ipwho?.security?.tor ?? null,
            is_datacenter: ipapi?.is_datacenter ?? (ipwho?.connection?.type === 'hosting' ? true : null),
            is_abuser: ipapi?.is_abuser ?? ipwho?.security?.abuser ?? null,
            is_attacker: ipwho?.security?.attacker ?? null,
            is_threat: ipwho?.security?.threat ?? null,
            anonymous: ipwho?.security?.anonymous ?? null,
            matrix_risk: matrix?.risk ? matrix.risk : null,
            high_risk_asn: highRiskAsn || null,
            verified_bot_asn: verifiedBot || null,
            vpn_cache: vpnCached,
            velocity_window: velocity
        });
        const company = pick({
            name: ipapi?.company?.name || ipwho?.connection?.org || null,
            abuser_score: ipapi?.company?.abuser_score ?? null,
            type: ipapi?.company?.type || null
        });
        const metrics = trustCard?.metrics
            ? pick({
                risk_percent: trustCard.metrics.risk_percent ?? null,
                anon_percent: trustCard.metrics.anon_percent ?? null,
                fraud_percent: trustCard.metrics.fraud_percent ?? null,
                abuse_percent: trustCard.metrics.abuse_percent ?? null,
                signal_confidence: trustCard.metrics.signal_confidence ?? null,
                detection_level: trustCard.metrics.detection_level ?? null
            })
            : {};
        return {
            target,
            generated_at: new Date().toISOString(),
            sources,
            observed: observed && Object.keys(pick(observed)).length ? observed : undefined,
            live: {
                policy_mode: policyMode || null,
                verdict: evaluation?.verdict || trustCard?.verdict || null,
                score: evaluation?.score ?? trustCard?.trust_score ?? null,
                latency_ms: evaluation?.latency_ms ?? null,
                signals: (evaluation?.signals || []).map((s) => ({
                    id: s.id,
                    label: s.label,
                    weight: s.weight
                })),
                network,
                geo,
                security,
                company: Object.keys(company).length ? company : undefined,
                metrics: Object.keys(metrics).length ? metrics : undefined,
                flags: trustCard?.telemetry_flags?.length ? trustCard.telemetry_flags : undefined
            },
            history: hist.history
        };
    }
}
exports.DossierService = DossierService;
