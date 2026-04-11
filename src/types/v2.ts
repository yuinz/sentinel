export type Verdict = 'ALLOW' | 'CHALLENGE' | 'BLOCK';

export type PolicyMode = 'PASSIVE' | 'BALANCED' | 'STRICT' | 'DRACONIAN' | 'HUMAN_ONLY';

export type ActionType = 'allow' | 'challenge' | 'block';

export interface V2PolicyConfig {
    mode: PolicyMode;
    allowed_asns?: number[];
    blocked_asns?: number[];
    allowed_countries?: string[];
    blocked_countries?: string[];
    rules?: string[]; // Custom DSL. Example: ["IF signal == 'VERIFIED_BOT' THEN ALLOW"]
    // Dashboard-configurable flags
    vpn_action?: ActionType;
    datacenter_action?: ActionType;
    force_bwt?: boolean;
    exempt_server_requests?: boolean;
    difficulty_level?: number;
}


export type SignalId = 
    | 'TOKEN_VALID' 
    | 'RESIDENTIAL_IP'
    | 'VPN_DETECTED' 
    | 'DATACENTER_IP' 
    | 'HIGH_VELOCITY'
    | 'VERIFIED_BOT'
    | 'SCANNER_PATTERN';

export interface TrustSignal {
    id: SignalId | string; // Allow custom strings for flexibility, but strongly type the core signals
    weight: number; 
    label: string;
}

export interface EvaluationResult {
    verdict: Verdict;
    score: number;
    signals: TrustSignal[];
    latency_ms: number;
    action_required?: 'SOLVE_CAPTCHA' | 'SILENT_CHALLENGE';
}
