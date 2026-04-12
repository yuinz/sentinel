/**
 * Sentinel Frontend SDK (Behavioral Work Token Solver)
 * Provides cryptographically secure intent detection in the browser.
 */

class SentinelEngine {
    constructor(config = {}) {
        this.endpoint = config.endpoint || 'https://sentinel.risksignal.name.ng';
        this.debug = config.debug || false;
        this.siteKey = config.siteKey || null;
    }

    init(siteKey) {
        this.siteKey = siteKey;
    }

    log(...msgs) {
        if (this.debug) console.log('[Sentinel]', ...msgs);
    }

    /**
     * Compute SHA-256 hash using the Web Crypto API
     */
    async sha256(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Solves the Proof-of-Work locally in the browser.
     * Complexity is low enough to be sub-second but high enough to break script farms.
     */
    async solveChallenge(noncePrefix, difficulty) {
        this.log('Solving cryptographic challenge...', { prefix: noncePrefix, difficulty });
        
        const targetHex = "0".repeat(difficulty);
        let currentNonce = 0;

        while (true) {
            const attempt = `${noncePrefix}_${currentNonce}`;
            const hash = await this.sha256(attempt);

            if (hash.startsWith(targetHex)) {
                this.log(`Challenge solved in ${currentNonce} iterations!`);
                return attempt;
            }
            currentNonce++;
            
            // Allow main thread to breathe every 5000 iterations
            if (currentNonce % 5000 === 0) {
                await new Promise(resolve => setTimeout(resolve, 0));
            }
        }
    }

    /**
     * Completes an invisible intent verification.
     * Required when an IP receives an 'UNSTABLE' or 'CHALLENGE' verdict.
     * 
     * @param {string} targetIp - IP to verify. Defaults to 'detect' which lets the backend
     *                             resolve the real client IP from connection headers automatically.
     * @param {string} context  - Context label for telemetry (e.g. 'browser', 'checkout').
     */
    async verify(targetIp = 'detect', context = 'browser') {
        try {
            // 1. Request the challenge from the Sentinel node
            this.log(`Requesting challenge for target: ${targetIp}`);
            
            const headers = { 'Content-Type': 'application/json' };
            if (this.siteKey) headers['Authorization'] = `Bearer ${this.siteKey}`;
            
            const issueRes = await fetch(`${this.endpoint}/v1/challenge/issue`, {
                method: 'POST',
                headers,
                body: JSON.stringify({ target: targetIp, context })
            });

            if (!issueRes.ok) throw new Error('Failed to fetch Sentinel challenge from node.');
            const challenge = await issueRes.json();

            if (challenge.type !== 'BWT') {
                return { success: true, bypassed: true };
            }

            // 2. Solve the challenge cryptographically
            const solvedNonce = await this.solveChallenge(challenge.nonce_prefix, challenge.difficulty);

            // 3. Submit solution to receive Trust Token
            this.log('Submitting solved nonce...');
            
            const verifyHeaders = { 'Content-Type': 'application/json' };
            if (this.siteKey) verifyHeaders['Authorization'] = `Bearer ${this.siteKey}`;

            const verifyRes = await fetch(`${this.endpoint}/v1/challenge/verify`, {
                method: 'POST',
                headers: verifyHeaders,
                body: JSON.stringify({ target: targetIp, nonce: solvedNonce })
            });

            const result = await verifyRes.json();
            
            if (result.success) {
                this.log('Verification successful! Trust Token received.', result.trust_token);
                // Save contextually (local storage)
                localStorage.setItem('sentinel_trust_token', result.trust_token);
                return { success: true, token: result.trust_token };
            } else {
                throw new Error(result.error || 'Verification failed');
            }
            
        } catch (e) {
            console.error('[Sentinel] Verification Error:', e.message);
            return { success: false, error: e.message };
        }
    }

    /**
     * Helper to automatically attach the Trust Token to Fetch API headers
     */
    getAuthHeaders() {
        const token = localStorage.getItem('sentinel_trust_token');
        return token ? { 'x-sentinel-trust': token } : {};
    }
}

// Auto-initialize globally for script-tag users
window.Sentinel = new SentinelEngine();
