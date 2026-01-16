/**
 * Sentinel Widget (Alpha v1.0)
 * Simple, Decoupled, Economic Friction Gate
 * 
 * Usage: 
 * <div id="sentinel-widget" data-sitekey="YOUR_KEY"></div>
 * <script src="/sentinel-widget.js"></script>
 */

(function () {
    const style = `
        .sentinel-widget-container {
            width: 300px;
            height: 65px;
            background: #0f0f0f;
            border: 1px solid #1f1f1f;
            border-radius: 8px;
            display: flex;
            align-items: center;
            padding: 0 15px;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: #fff;
            user-select: none;
            cursor: pointer;
            position: relative;
            overflow: hidden;
            transition: all 0.2s ease;
        }

        .sentinel-widget-container:hover {
            border-color: #333;
            background: #151515;
        }

        .sentinel-icon {
            width: 24px;
            height: 24px;
            margin-right: 12px;
            color: #00ff88;
            transition: transform 0.3s ease;
            z-index: 2;
        }

        .sentinel-text-container {
            display: flex;
            flex-direction: column;
            z-index: 2;
        }

        .sentinel-label {
            font-size: 13px;
            font-weight: 600;
        }

        .sentinel-subtext {
            font-size: 10px;
            color: #888;
            margin-top: 2px;
            letter-spacing: 0.02em;
        }

        .sentinel-progress-overlay {
            position: absolute;
            left: 0;
            top: 0;
            height: 100%;
            width: 0%;
            background: rgba(0, 255, 136, 0.08);
            border-right: 2px solid #00ff88;
            z-index: 1;
            transition: width 0.1s linear;
        }

        .sentinel-success .sentinel-icon {
            transform: scale(1.1);
        }

        .sentinel-success {
            cursor: default;
            border-color: #00ff8866;
        }

        .sentinel-brand {
            position: absolute;
            right: 12px;
            bottom: 6px;
            font-size: 9px;
            color: #444;
            font-weight: 700;
            letter-spacing: 0.05em;
        }
    `;

    const injectStyles = () => {
        const s = document.createElement('style');
        s.innerHTML = style;
        document.head.appendChild(s);
    };

    class SentinelWidget {
        constructor(el) {
            this.el = el;
            this.duration = 2500; // Default 2.5s
            this.isHolding = false;
            this.startTime = null;
            this.isVerified = false;

            this.init();
        }

        init() {
            this.el.classList.add('sentinel-widget-container');
            this.el.innerHTML = `
                <div class="sentinel-progress-overlay" id="sentinel-progress"></div>
                <!-- RiskSignal Branded Icon -->
                <svg class="sentinel-icon" id="sentinel-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                    <path d="M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3z" stroke-width="2"/>
                    <circle cx="12" cy="12" r="2" fill="currentColor" stroke="none"/>
                    <path d="M12 8c2.21 0 4 1.79 4 4" stroke-width="1.5" stroke-linecap="round"/>
                    <path d="M12 5c3.87 0 7 3.13 7 7" stroke-width="1.5" stroke-linecap="round"/>
                </svg>
                <div class="sentinel-text-container">
                    <div class="sentinel-label" id="sentinel-label">Verify request</div>
                    <div class="sentinel-subtext" id="sentinel-sub">Click and hold to continue</div>
                </div>
                <div class="sentinel-brand">SENTINEL</div>
            `;

            this.progress = this.el.querySelector('#sentinel-progress');
            this.label = this.el.querySelector('#sentinel-label');
            this.sub = this.el.querySelector('#sentinel-sub');
            this.icon = this.el.querySelector('#sentinel-icon');

            this.el.addEventListener('mousedown', (e) => this.start(e));
            window.addEventListener('mouseup', () => this.stop());

            this.el.addEventListener('touchstart', (e) => this.start(e));
            window.addEventListener('touchend', () => this.stop());
        }

        start(e) {
            if (this.isVerified) return;
            e.preventDefault();
            this.isHolding = true;
            this.startTime = Date.now();
            this.label.innerText = "Holding...";
            this.animate();
        }

        stop() {
            if (!this.isHolding || this.isVerified) return;
            this.isHolding = false;
            const elapsed = Date.now() - this.startTime;

            if (elapsed < this.duration) {
                this.progress.style.width = '0%';
                this.label.innerText = "Verify request";
                this.sub.innerText = "Released too early";
                this.sub.style.color = "#ff4444";
            }
        }

        animate() {
            if (!this.isHolding || this.isVerified) return;

            const elapsed = Date.now() - this.startTime;
            const ratio = Math.min(elapsed / this.duration, 1);
            this.progress.style.width = `${ratio * 100}%`;

            if (ratio < 1) {
                requestAnimationFrame(() => this.animate());
            } else {
                this.complete();
            }
        }

        complete() {
            this.isVerified = true;
            this.isHolding = false;
            this.el.classList.add('sentinel-success');
            this.label.innerText = "Verified";
            this.sub.innerText = "Trust token issued";
            this.sub.style.color = "#00ff88";
            this.icon.setAttribute('fill', 'none');
            this.icon.setAttribute('stroke', 'currentColor');
            this.icon.innerHTML = `
                <path d="M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3z" stroke-width="2"/>
                <path d="M9 12l2 2 4-4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            `;

            // Dispatch event for developer
            const event = new CustomEvent('sentinel-verified', {
                detail: { token: "sentinel_trust_demo_" + Math.random().toString(36).substring(7) }
            });
            this.el.dispatchEvent(event);
        }
    }

    injectStyles();
    document.querySelectorAll('#sentinel-widget').forEach(el => new SentinelWidget(el));
})();
