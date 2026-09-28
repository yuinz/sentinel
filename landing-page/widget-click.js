(function () {
    const WIDGET_ID = 'sentinel-click-widget';
    const scriptUrl = document.currentScript ? document.currentScript.src : 'https://sentinel.risksignal.name.ng/widget-click.js';
    const API_BASE = new URL(scriptUrl).origin;

    function rotr(x, n) {
        return (x >>> n) | (x << (32 - n));
    }

    // Sync SHA-256 so difficulty 1–5 finishes in the browser. Output matches Node's createHash('sha256').
    function sha256Hex(message) {
        const K = new Uint32Array([
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]);
        const bytes = new TextEncoder().encode(message);
        const padded = new Uint8Array(((bytes.length + 9 + 63) >> 6) << 6);
        padded.set(bytes);
        padded[bytes.length] = 0x80;
        const view = new DataView(padded.buffer);
        const bits = bytes.length * 8;
        view.setUint32(padded.length - 8, Math.floor(bits / 0x100000000));
        view.setUint32(padded.length - 4, bits >>> 0);

        let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
        let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
        const w = new Uint32Array(64);

        for (let i = 0; i < padded.length; i += 64) {
            for (let t = 0; t < 16; t++) w[t] = view.getUint32(i + t * 4);
            for (let t = 16; t < 64; t++) {
                const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
                const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
                w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
            }
            let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
            for (let t = 0; t < 64; t++) {
                const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                const ch = (e & f) ^ (~e & g);
                const t1 = (h + S1 + ch + K[t] + w[t]) >>> 0;
                const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                const maj = (a & b) ^ (a & c) ^ (b & c);
                const t2 = (S0 + maj) >>> 0;
                h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
            }
            h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
            h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
        }
        return [h0, h1, h2, h3, h4, h5, h6, h7].map((x) => x.toString(16).padStart(8, '0')).join('');
    }

    class SentinelClickWidget {
        constructor(container) {
            this.container = container;
            this.siteKey = container.getAttribute('data-sitekey');
            this.state = 'idle';
            this.run = 0;
            this.setupShadowDOM();
            this.render();
        }

        setupShadowDOM() {
            this.shadow = this.container.attachShadow({ mode: 'open' });
            const style = document.createElement('style');
            style.textContent = `
                :host {
                    display: block;
                    width: 248px;
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                }

                .widget-box {
                    background: #0d0d0d;
                    border: 1px solid #1f1f1f;
                    border-radius: 10px;
                    padding: 7px 10px 8px;
                    position: relative;
                    overflow: hidden;
                    cursor: pointer;
                    user-select: none;
                    display: grid;
                    grid-template-columns: 16px minmax(0, 1fr) auto;
                    grid-template-areas:
                        "icon label mark"
                        "sub  sub   links";
                    column-gap: 8px;
                    row-gap: 2px;
                    align-items: center;
                    transition: border-color 0.2s ease;
                    box-shadow: 0 1px 2px rgba(0,0,0,0.35);
                }
                .widget-box:hover { border-color: #2e2e2e; }
                [data-state="success"] .widget-box,
                [data-state="success"] .widget-box:hover {
                    cursor: default;
                    border-color: rgba(0, 232, 122, 0.28);
                }

                .status-icon {
                    grid-area: icon;
                    position: relative;
                    width: 16px;
                    height: 16px;
                    box-sizing: border-box;
                    border: 1.5px solid #3a3a3a;
                    border-radius: 4px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 11px;
                    line-height: 1;
                    color: transparent;
                    background: #111;
                }
                .status-icon:focus { outline: none; }
                .status-icon:focus-visible {
                    outline: 2px solid #d0d0d0;
                    outline-offset: 2px;
                }
                .status-icon.busy { color: transparent; }
                .status-icon.busy::after {
                    content: '';
                    position: absolute;
                    inset: 2px;
                    border-radius: 50%;
                    border: 1.5px solid #333;
                    border-top-color: #e8e8e8;
                    animation: spin 0.7s linear infinite;
                }
                .status-icon.active {
                    border-color: #00e87a;
                    color: #00e87a;
                    background: rgba(0, 232, 122, 0.08);
                }
                .status-icon.active::after { display: none; }
                [data-state="error"] .status-icon {
                    border-color: #ff5a5a;
                    background: rgba(255, 90, 90, 0.08);
                    color: transparent;
                }
                @keyframes spin { to { transform: rotate(360deg); } }
                @media (prefers-reduced-motion: reduce) {
                    .status-icon.busy::after { animation: none; border-color: #e8e8e8; }
                }

                .label {
                    grid-area: label;
                    min-width: 0;
                    font-size: 11px;
                    font-weight: 600;
                    color: #f2f2f2;
                    letter-spacing: -0.01em;
                    line-height: 1.2;
                    white-space: nowrap;
                    overflow: hidden;
                    text-overflow: ellipsis;
                }
                .sub-label {
                    grid-area: sub;
                    min-width: 0;
                    min-height: 10px;
                    font-size: 8.5px;
                    font-weight: 500;
                    color: #9a9a9a;
                    text-transform: uppercase;
                    letter-spacing: 0.04em;
                    line-height: 1.2;
                    white-space: nowrap;
                    overflow: hidden;
                    text-overflow: ellipsis;
                }

                .brand-mark {
                    grid-area: mark;
                    display: flex;
                    align-items: center;
                    gap: 4px;
                }
                .brand-icon svg {
                    display: block;
                    width: 12px;
                    height: 12px;
                }
                .brand-name {
                    font-size: 7px;
                    font-weight: 700;
                    color: #8a8a8a;
                    text-transform: uppercase;
                    letter-spacing: 0.08em;
                    line-height: 1;
                }
                .brand-links {
                    grid-area: links;
                    display: flex;
                    align-items: center;
                    justify-self: end;
                    gap: 4px;
                    line-height: 1;
                }
                .brand-links a {
                    font-size: 7px;
                    font-weight: 600;
                    color: #8d8d8d;
                    text-decoration: none;
                    text-transform: uppercase;
                    letter-spacing: 0.04em;
                    cursor: pointer;
                }
                .brand-links a:hover,
                .brand-links a:focus-visible { color: #f2f2f2; }
                .brand-sep {
                    font-size: 7px;
                    color: #555;
                    line-height: 1;
                }

                .progress-bar {
                    position: absolute;
                    bottom: 0;
                    left: 0;
                    height: 2px;
                    width: 0%;
                    background: #00e87a;
                    z-index: 3;
                }
            `;
            this.shadow.appendChild(style);
        }

        render() {
            this.wrapper = document.createElement('div');
            this.wrapper.className = 'widget-box';
            this.wrapper.innerHTML = `
                <div class="status-icon" id="icon" role="checkbox" aria-checked="false" aria-label="Verify you're human" tabindex="0">&#10003;</div>
                <div class="label" id="label" aria-live="polite">Verify you're human</div>
                <div class="brand-mark">
                    <div class="brand-icon" aria-hidden="true">
                        <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.35C16.6 22.15 20 17.25 20 12V6l-8-4z" fill="#00e87a"/>
                            <path d="M9 12l2 2 4-4" stroke="#0d0d0d" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                    </div>
                    <div class="brand-name">Sentinel</div>
                </div>
                <div class="sub-label" id="sub">Click to verify</div>
                <div class="brand-links">
                    <a href="https://sentinel.risksignal.name.ng/privacy.html" target="_blank" rel="noopener">Privacy</a>
                    <span class="brand-sep" aria-hidden="true">·</span>
                    <a href="https://sentinel.risksignal.name.ng/terms.html" target="_blank" rel="noopener">Terms</a>
                </div>
                <div class="progress-bar" id="progress"></div>
            `;
            this.shadow.appendChild(this.wrapper);

            this.wrapper.addEventListener('click', (e) => this.start(e));
            this.shadow.getElementById('icon').addEventListener('keydown', (e) => {
                if (e.key !== 'Enter' && e.key !== ' ') return;
                e.preventDefault();
                this.start(e);
            });
        }

        async start(e) {
            if (e.target.closest && e.target.closest('a')) return;
            if (this.state === 'working' || this.state === 'success') return;

            const run = ++this.run;
            this.state = 'working';
            this.wrapper.dataset.state = 'working';
            this.wrapper.setAttribute('aria-busy', 'true');
            const icon = this.shadow.getElementById('icon');
            icon.classList.add('busy');
            icon.classList.remove('active');
            icon.setAttribute('aria-checked', 'false');
            this.setProgress(0);
            this.updateUI("Verify you're human", 'Verifying');

            try {
                const issued = await fetch(`${API_BASE}/v1/challenge/issue`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${this.siteKey}`
                    },
                    body: JSON.stringify({ target: 'detect', context: 'widget-click' })
                });
                if (run !== this.run) return;
                if (!issued.ok) throw new Error('issue');
                const challenge = await issued.json();
                const prefix = String(challenge.nonce_prefix || '');
                const difficulty = Number(prefix.charAt(8));
                if (prefix.length < 9 || difficulty < 1 || difficulty > 5) throw new Error('issue');

                const nonce = await this.solvePoW(prefix, difficulty, run);
                if (run !== this.run) return;

                const verified = await fetch(`${API_BASE}/v1/challenge/verify`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${this.siteKey}`
                    },
                    body: JSON.stringify({ target: 'detect', nonce })
                });
                if (run !== this.run) return;
                const result = await verified.json();
                if (!verified.ok || !result.success || !result.trust_token) throw new Error('verify');

                this.finish(result);
            } catch (err) {
                if (run !== this.run) return;
                this.fail();
            }
        }

        finish(result) {
            this.state = 'success';
            this.wrapper.dataset.state = 'success';
            this.wrapper.setAttribute('aria-busy', 'false');
            const icon = this.shadow.getElementById('icon');
            icon.classList.remove('busy');
            icon.classList.add('active');
            icon.setAttribute('aria-checked', 'true');
            icon.setAttribute('aria-label', 'Verified');
            this.setProgress(1);
            this.updateUI('Verified', '');
            this.injectToken(result.trust_token);
            document.dispatchEvent(new CustomEvent('sentinelSuccess', { detail: result }));
        }

        fail() {
            this.state = 'error';
            this.wrapper.dataset.state = 'error';
            this.wrapper.setAttribute('aria-busy', 'false');
            const icon = this.shadow.getElementById('icon');
            icon.classList.remove('busy', 'active');
            icon.setAttribute('aria-checked', 'false');
            icon.setAttribute('aria-label', 'Try again');
            this.setProgress(0);
            this.updateUI('Try again', 'Click to verify');
        }

        async solvePoW(prefix, difficulty, run) {
            const zeros = '0'.repeat(difficulty);
            const expected = 16 ** difficulty;
            let nonce = 0;

            while (nonce <= 8000000) {
                const candidate = prefix + nonce;
                if (sha256Hex(candidate).startsWith(zeros)) {
                    this.setProgress(1);
                    return candidate;
                }
                nonce++;
                if (nonce % 1000 === 0) {
                    if (run !== this.run) throw new Error('stale');
                    this.setProgress(Math.min(nonce / expected, 0.92));
                    await new Promise((resolve) => setTimeout(resolve, 0));
                }
            }
            throw new Error('proof');
        }

        setProgress(ratio) {
            this.shadow.getElementById('progress').style.width = `${Math.round(ratio * 100)}%`;
        }

        updateUI(label, sub) {
            this.shadow.getElementById('label').textContent = label;
            this.shadow.getElementById('sub').textContent = sub;
        }

        injectToken(token) {
            const form = this.container.closest('form');
            if (!form) return;
            let input = form.querySelector('input[name="sentinel-token"]');
            if (!input) {
                input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'sentinel-token';
                form.appendChild(input);
            }
            input.value = token;
        }
    }

    const target = document.getElementById(WIDGET_ID);
    if (target && !target.shadowRoot) new SentinelClickWidget(target);
})();
