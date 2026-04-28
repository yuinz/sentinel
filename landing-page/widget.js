(function () {
    const WIDGET_ID = 'sentinel-widget';
    const scriptUrl = document.currentScript ? document.currentScript.src : 'https://sentinel.risksignal.name.ng/widget.js';
    const API_BASE = new URL(scriptUrl).origin;

    class SentinelWidget {
        constructor(container) {
            this.container = container;
            this.siteKey = container.getAttribute('data-sitekey');
            this.state = 'idle'; // idle, issuing, holding, verifying, success, error
            this.challenge = null;
            this.isHolding = false;
            this.startTime = null;
            this.animationFrame = null;

            this.setupShadowDOM();
            this.render();
        }

        setupShadowDOM() {
            this.shadow = this.container.attachShadow({ mode: 'open' });
            this.styles = document.createElement('style');
            this.styles.textContent = `
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

                :host {
                    display: block;
                    width: 300px;
                    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                }

                /* ── Card ─────────────────────────────────────── */
                .widget-box {
                    background: #0d0d0d;
                    border: 1px solid #1f1f1f;
                    border-radius: 10px;
                    padding: 14px 16px 10px;
                    position: relative;
                    overflow: hidden;
                    cursor: pointer;
                    user-select: none;
                    transition: border-color 0.25s ease, box-shadow 0.25s ease;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.4);
                }
                .widget-box:hover {
                    border-color: #2a2a2a;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.5);
                }

                /* ── Main row ─────────────────────────────────── */
                .widget-content {
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    position: relative;
                    z-index: 2;
                }

                /* ── Checkbox ─────────────────────────────────── */
                .status-icon {
                    flex-shrink: 0;
                    width: 22px;
                    height: 22px;
                    border: 2px solid #2d2d2d;
                    border-radius: 5px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 13px;
                    color: transparent;
                    transition: border-color 0.3s, background 0.3s, color 0.3s;
                    background: #111;
                }
                .status-icon.active {
                    border-color: #00e87a;
                    color: #00e87a;
                    background: rgba(0, 232, 122, 0.08);
                }

                /* ── Text ─────────────────────────────────────── */
                .text-payload { flex: 1; min-width: 0; }
                .label {
                    font-size: 13px;
                    font-weight: 600;
                    color: #e8e8e8;
                    margin-bottom: 2px;
                    letter-spacing: -0.01em;
                    white-space: nowrap;
                    overflow: hidden;
                    text-overflow: ellipsis;
                }
                .sub-label {
                    font-size: 10px;
                    font-weight: 500;
                    color: #484848;
                    text-transform: uppercase;
                    letter-spacing: 0.07em;
                    transition: color 0.2s;
                }

                /* ── Logo / Brand ─────────────────────────────── */
                .brand {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    gap: 3px;
                    flex-shrink: 0;
                }
                .brand-icon svg {
                    display: block;
                    width: 20px;
                    height: 20px;
                    opacity: 0.45;
                    transition: opacity 0.2s;
                }
                .widget-box:hover .brand-icon svg { opacity: 0.7; }
                .brand-name {
                    font-size: 8px;
                    font-weight: 700;
                    color: #363636;
                    text-transform: uppercase;
                    letter-spacing: 0.12em;
                    transition: color 0.2s;
                }
                .widget-box:hover .brand-name { color: #484848; }

                /* ── Progress bar ─────────────────────────────── */
                .progress-bar {
                    position: absolute;
                    bottom: 0;
                    left: 0;
                    height: 2px;
                    background: linear-gradient(90deg, #00e87a, #00bfff);
                    width: 0%;
                    transition: width 0.08s linear;
                    z-index: 3;
                }
                .progress-bar::after {
                    content: '';
                    position: absolute;
                    top: 0; right: 0;
                    width: 40px; height: 100%;
                    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.35));
                    animation: shimmer 1s ease infinite;
                }
                @keyframes shimmer {
                    0%   { opacity: 0; }
                    50%  { opacity: 1; }
                    100% { opacity: 0; }
                }

                /* ── Divider ──────────────────────────────────── */
                .divider {
                    height: 1px;
                    background: #181818;
                    margin: 10px -16px 8px;
                }

                /* ── Footer ───────────────────────────────────── */
                .footer {
                    display: flex;
                    align-items: center;
                    justify-content: flex-end;
                    gap: 10px;
                    position: relative;
                    z-index: 2;
                }
                .footer a {
                    font-size: 9.5px;
                    font-weight: 500;
                    color: #343434;
                    text-decoration: none;
                    text-transform: uppercase;
                    letter-spacing: 0.06em;
                    transition: color 0.2s;
                    pointer-events: auto;
                    cursor: pointer;
                }
                .footer a:hover { color: #666; }
                .footer-sep {
                    font-size: 9px;
                    color: #252525;
                }

                /* ── Success state ────────────────────────────── */
                [data-state="success"] .status-icon {
                    border-color: #00e87a;
                    background: rgba(0, 232, 122, 0.08);
                    color: #00e87a;
                }
                [data-state="success"] .widget-box {
                    border-color: rgba(0, 232, 122, 0.25);
                }

                /* ── Error state ──────────────────────────────── */
                [data-state="error"] .status-icon {
                    border-color: #ff4444;
                    background: rgba(255, 68, 68, 0.08);
                    color: #ff4444;
                }
            `;
            this.shadow.appendChild(this.styles);
        }

        render() {
            this.wrapper = document.createElement('div');
            this.wrapper.className = 'widget-box';
            this.wrapper.innerHTML = `
                <div class="widget-content">
                    <div class="status-icon" id="icon">&#10003;</div>
                    <div class="text-payload">
                        <div class="label" id="label">Verify you're human</div>
                        <div class="sub-label" id="sub">Hold to verify</div>
                    </div>
                    <div class="brand">
                        <div class="brand-icon">
                            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <path d="M12 2L4 6v6c0 5.25 3.4 10.15 8 11.35C16.6 22.15 20 17.25 20 12V6l-8-4z" fill="#00e87a" opacity="0.9"/>
                                <path d="M9 12l2 2 4-4" stroke="#0d0d0d" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        </div>
                        <div class="brand-name">Sentinel</div>
                    </div>
                </div>
                <div class="divider"></div>
                <div class="footer">
                    <a href="https://sentinel.risksignal.name.ng/privacy.html" target="_blank" rel="noopener">Privacy</a>
                    <span class="footer-sep">·</span>
                    <a href="https://sentinel.risksignal.name.ng/terms.html" target="_blank" rel="noopener">Terms</a>
                </div>
                <div class="progress-bar" id="progress"></div>
            `;

            this.shadow.appendChild(this.wrapper);

            this.wrapper.addEventListener('mousedown', (e) => this.startHold(e));
            window.addEventListener('mouseup', () => this.stopHold());
            this.wrapper.addEventListener('touchstart', (e) => this.startHold(e));
            window.addEventListener('touchend', () => this.stopHold());
        }


        async startHold(e) {
            if (this.state === 'success' || this.state === 'issuing') return;

            this.isHolding = true;
            this.startTime = Date.now();
            this.state = 'issuing';
            this.updateUI('Holding...', 'Establishing Secure Tunnel', '#00ff88');

            try {
                // 1. Issue Challenge
                const response = await fetch(`${API_BASE}/v1/challenge/issue`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${this.siteKey}`
                    },
                    body: JSON.stringify({ target: 'detect', context: 'widget' })
                });
                this.challenge = await response.json();
                this.state = 'holding';
                this.animate();
            } catch (err) {
                this.state = 'error';
                this.updateUI('Failed', 'API Connection Error', '#ff4444');
            }
        }

        stopHold() {
            if (!this.isHolding) return;
            this.isHolding = false;

            if (this.state !== 'success') {
                this.state = 'idle';
                this.updateUI('Verify Intent', 'Released too early', '#666');
                this.shadow.getElementById('progress').style.width = '0%';
            }
            if (this.animationFrame) cancelAnimationFrame(this.animationFrame);
        }

        animate() {
            if (!this.isHolding || this.state !== 'holding') return;

            const duration = (this.challenge.behavioral_duration || 2) * 1000;
            const elapsed = Date.now() - this.startTime;
            const ratio = Math.min(elapsed / duration, 1);

            this.shadow.getElementById('progress').style.width = `${ratio * 100}%`;

            if (ratio < 1) {
                this.animationFrame = requestAnimationFrame(() => this.animate());
            } else {
                this.verify();
            }
        }

        async verify() {
            this.state = 'verifying';
            this.updateUI('Verifying...', 'Computing Proof of Work', '#0af');

            // 2. Solve PoW Nonce
            const nonce = await this.solvePoW(this.challenge.nonce_prefix, this.challenge.difficulty);

            try {
                const response = await fetch(`${API_BASE}/v1/challenge/verify`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${this.siteKey}`
                    },
                    body: JSON.stringify({
                        target: 'detect',
                        nonce: nonce
                    })
                });
                const result = await response.json();

                if (result.success) {
                    this.state = 'success';
                    this.updateUI('Verified', 'Trust Token Issued', '#00ff88');
                    this.wrapper.style.borderColor = '#00ff88';
                    this.wrapper.style.background = 'rgba(0, 255, 136, 0.05)';
                    this.shadow.getElementById('icon').classList.add('active');

                    // Create hidden input in parent form if exists
                    this.injectToken(result.trust_token);

                    // Fire Event
                    const event = new CustomEvent('sentinelSuccess', { detail: result });
                    document.dispatchEvent(event);
                } else {
                    throw new Error('Verification failed');
                }
            } catch (err) {
                this.state = 'error';
                this.updateUI('Denied', 'Behavioral Anomaly Detected', '#ff4444');
            }
        }

        async solvePoW(prefix, difficulty) {
            const target = '0'.repeat(difficulty);
            let nonce = 0;
            const encoder = new TextEncoder();

            while (true) {
                const data = encoder.encode(prefix + nonce);
                const hashBuffer = await crypto.subtle.digest('SHA-256', data);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

                if (hashHex.startsWith(target)) {
                    return prefix + nonce;
                }
                nonce++;
                if (nonce > 1000000) return nonce; // Safety break
            }
        }

        updateUI(label, sub, color) {
            this.shadow.getElementById('label').innerText = label;
            this.shadow.getElementById('sub').innerText = sub;
            this.shadow.getElementById('sub').style.color = color;
        }

        injectToken(token) {
            const form = this.container.closest('form');
            if (form) {
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
    }

    // Auto-init
    const target = document.getElementById(WIDGET_ID);
    if (target) {
        new SentinelWidget(target);
        console.log("🛡️ Sentinel Widget Active");
    }
})();
