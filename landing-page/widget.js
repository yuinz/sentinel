(function () {
    const WIDGET_ID = 'sentinel-widget';
    const scriptUrl = document.currentScript ? document.currentScript.src : 'https://sentinel.risksignal.name.ng/widget.js';
    const API_BASE = new URL(scriptUrl).origin;

    class SentinelWidget {
        constructor(container) {
            this.container = container;
            this.siteKey = container.getAttribute('data-sitekey');
            this.target = 'client-ip'; // Backend will resolve
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
                :host {
                    display: block;
                    width: 300px;
                    font-family: 'Inter', -apple-system, sans-serif;
                }
                .widget-box {
                    background: #0a0a0a;
                    border: 1px solid #1a1a1a;
                    border-radius: 8px;
                    padding: 12px 16px;
                    position: relative;
                    overflow: hidden;
                    cursor: pointer;
                    user-select: none;
                    transition: border-color 0.3s, background 0.3s;
                }
                .widget-box:hover { border-color: #333; }
                .widget-content {
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    position: relative;
                    z-index: 2;
                }
                .status-icon {
                    width: 20px;
                    height: 20px;
                    border: 2px solid #333;
                    border-radius: 4px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 10px;
                    color: transparent;
                    transition: all 0.3s;
                }
                .status-icon.active { border-color: #00ff88; color: #00ff88; }
                .text-payload { flex: 1; }
                .label {
                    font-size: 13px;
                    font-weight: 600;
                    color: #eee;
                    margin-bottom: 2px;
                }
                .sub-label {
                    font-size: 10px;
                    color: #555;
                    text-transform: uppercase;
                    letter-spacing: 0.05em;
                }
                .progress-bar {
                    position: absolute;
                    bottom: 0;
                    left: 0;
                    height: 2px;
                    background: #00ff88;
                    width: 0%;
                    transition: width 0.1s linear;
                }
                .logo {
                    font-family: monospace;
                    font-size: 10px;
                    color: #333;
                    font-weight: bold;
                }
                .success-check { color: #00ff88; display: none; }
                [data-state="success"] .success-check { display: block; }
                [data-state="success"] .status-icon { border-color: #00ff88; background: rgba(0, 255, 136, 0.1); }
            `;
            this.shadow.appendChild(this.styles);
        }

        render() {
            this.wrapper = document.createElement('div');
            this.wrapper.className = 'widget-box';
            this.wrapper.innerHTML = `
                <div class="widget-content">
                    <div class="status-icon" id="icon">✓</div>
                    <div class="text-payload">
                        <div class="label" id="label">Verify Intent</div>
                        <div class="sub-label" id="sub">Click and hold to secure</div>
                    </div>
                    <div class="logo">SENTINEL</div>
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
