const technicalInit = () => {
    const heroSubtitle = document.querySelector('.hero-subtitle');
    if (heroSubtitle) {
        const text = heroSubtitle.innerText;
        heroSubtitle.innerText = '';
        let i = 0;
        const type = () => {
            if (i < text.length) {
                heroSubtitle.innerText += text.charAt(i);
                i++;
                setTimeout(type, 15);
            }
        };
        type();
    }

    setInterval(() => {
        const technicalElements = document.querySelectorAll('.feature-badge, .highlight, .mono');
        technicalElements.forEach(el => {
            if (Math.random() > 0.98) {
                el.style.opacity = '0.3';
                setTimeout(() => el.style.opacity = '1', 40);
            }
        });
    }, 1500);
};

const setupDemoWidget = () => {
    const demoWidget = document.getElementById('demo-widget');
    if (!demoWidget) return;

    const demoProgress = document.getElementById('demo-progress');
    const demoLabel = document.getElementById('demo-label');
    const demoSub = document.getElementById('demo-sub');

    let isHolding = false;
    let startTime = null;
    const holdDuration = 2500;
    let animationFrame = null;

    const startHolding = (e) => {
        e.preventDefault();
        isHolding = true;
        startTime = Date.now();
        demoLabel.innerText = "ACCESSED";
        demoSub.innerText = "VERIFYING_INTENT_TOKEN";
        demoSub.style.color = "var(--accent)";
        animate();
    };

    const stopHolding = () => {
        if (!isHolding) return;
        isHolding = false;
        const elapsed = Date.now() - startTime;

        if (elapsed < holdDuration) {
            demoProgress.style.width = '0%';
            demoLabel.innerText = "ACCESS_DENIED";
            demoSub.innerText = "INTENT_PROOF_FAILURE";
            demoSub.style.color = "#ff4444";
            setTimeout(() => {
                demoLabel.innerText = "Verify request";
                demoSub.innerText = "Click and hold to continue";
                demoSub.style.color = "var(--text-dim)";
            }, 2000);
        }
        if (animationFrame) cancelAnimationFrame(animationFrame);
    };

    const animate = () => {
        if (!isHolding) return;
        const elapsed = Date.now() - startTime;
        const ratio = Math.min(elapsed / holdDuration, 1);
        demoProgress.style.width = `${ratio * 100}%`;

        if (ratio < 1) {
            animationFrame = requestAnimationFrame(animate);
        } else {
            complete();
        }
    };

    const complete = () => {
        isHolding = false;
        demoLabel.innerText = "VERIFIED";
        demoSub.innerText = "TRUST_TOKEN_ISSUED";
        demoSub.style.color = "var(--accent)";
        demoWidget.style.borderColor = "var(--accent)";
        demoWidget.style.background = "rgba(255, 0, 0, 0.05)";

        setTimeout(() => {
            demoProgress.style.width = '0%';
            demoLabel.innerText = "Verify request";
            demoSub.innerText = "Click and hold to continue";
            demoSub.style.color = "var(--text-dim)";
            demoWidget.style.borderColor = "var(--border)";
            demoWidget.style.background = "var(--bg-elevated)";
        }, 3000);
    };

    demoWidget.addEventListener('mousedown', startHolding);
    window.addEventListener('mouseup', stopHolding);
    demoWidget.addEventListener('touchstart', startHolding);
    window.addEventListener('touchend', stopHolding);
};

const setupRiskDemo = () => {
    const runBtn = document.getElementById('run-demo-btn');
    const result = document.getElementById('risk-result');
    const ipInput = document.getElementById('demo-ip-input');

    if (!runBtn) return;

    runBtn.addEventListener('click', () => {
        const ip = ipInput.value || "8.8.8.8";
        runBtn.innerText = 'SYNTHESIZING...';
        runBtn.disabled = true;
        result.style.display = 'none';

        setTimeout(() => {
            runBtn.innerText = 'CHECK TRUST';
            runBtn.disabled = false;
            result.style.display = 'flex';

            const firstOctet = parseInt(ip.split('.')[0]);
            let risk = 'STABLE';
            let score = 22;
            let color = 'var(--accent)';
            let signals = ['STRUCTURE: RESIDENTIAL_ISP', 'VELOCITY: NOMINAL', 'CARRIER: VERIFIED_MOBILE'];

            if (firstOctet > 200 || firstOctet < 30) {
                risk = 'UNTRUSTED';
                score = 88;
                color = '#ff0000';
                signals = ['ASN: HIGH_RISK_PROXY', 'REPUTATION: ABUSE_NODE_MATCH', 'VELOCITY: ANOMALY'];
            } else if (firstOctet > 100) {
                risk = 'UNSTABLE';
                score = 54;
                color = '#ffcc00';
                signals = ['ASN: CLOUD_INFRASTRUCTURE', 'REPUTATION: UNKNOWN', 'VELOCITY: SCAN_PATTERN'];
            }

            document.getElementById('risk-verdict').innerText = risk;
            document.getElementById('risk-tag').innerText = risk;
            document.getElementById('risk-tag').style.color = color;
            document.getElementById('risk-tag').style.background = `${color}11`;
            document.getElementById('risk-percentage').innerText = `${score}%`;
            document.getElementById('risk-circle-path').style.strokeDasharray = `${score}, 100`;
            document.getElementById('risk-circle-path').style.stroke = color;

            const list = document.getElementById('risk-signals');
            list.innerHTML = signals.map(s => `<li class="mono"><span style="color:${color}">//</span> ${s}</li>`).join('');
        }, 1200);
    });
};

const setupUtils = () => {
    const visual = document.querySelector('.hero-visual');
    window.addEventListener('mousemove', (e) => {
        if (!visual) return;
        const x = (e.clientX / window.innerWidth - 0.5) * 15;
        const y = (e.clientY / window.innerHeight - 0.5) * 15;
        visual.style.transform = `perspective(1000px) rotateY(${x}deg) rotateX(${-y}deg)`;
    });

    const header = document.querySelector('.main-header');
    window.addEventListener('scroll', () => {
        if (window.scrollY > 40) {
            header.style.background = 'rgba(0,0,0,0.95)';
            header.style.borderBottom = '1px solid #222';
        } else {
            header.style.background = 'rgba(0,0,0,0.8)';
            header.style.borderBottom = '1px solid transparent';
        }
    });

    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const code = btn.closest('.code-example').querySelector('code').innerText;
            navigator.clipboard.writeText(code).then(() => {
                btn.innerText = 'COPIED';
                setTimeout(() => btn.innerText = 'COPY', 2000);
            });
        });
    });
    const menuToggle = document.getElementById('menu-toggle');
    const navMenu = document.getElementById('nav-menu');

    if (menuToggle && navMenu) {
        menuToggle.addEventListener('click', () => {
            navMenu.classList.toggle('active');
            const icon = menuToggle.querySelector('svg');
            if (navMenu.classList.contains('active')) {
                icon.innerHTML = '<line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line>';
            } else {
                icon.innerHTML = '<line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line>';
            }
        });

        // Close menu when clicking a link
        navMenu.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', () => {
                navMenu.classList.remove('active');
                menuToggle.querySelector('svg').innerHTML = '<line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line>';
            });
        });
    }
};

const setupScrollReveal = () => {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('revealed');
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    // Apply reveal to elements that might already have the class or need it
    document.querySelectorAll('section, .feature-card, .problem-card, .stat, .blog-card, .reveal-on-scroll').forEach(el => {
        if (!el.classList.contains('reveal-on-scroll')) {
            el.classList.add('reveal-on-scroll');
        }
        observer.observe(el);
    });
};

const setupDynamicHero = () => {
    const heroTitle = document.querySelector('.hero-title');
    if (!heroTitle) return;

    const variations = [
        { main: "Bots Pay.", accent: "Human Pass.", color: "var(--accent)" },
        { main: "Malice Blocks.", accent: "Trust Flows.", color: "#00ff88" },
        { main: "Scripts Fail.", accent: "Users Sail.", color: "#00d2ff" },
        { main: "Scrapers Halt.", accent: "People Vault.", color: "#ff00ff" },
        { main: "Spam Dies.", accent: "Intent Flies.", color: "#ffaa00" },
        { main: "Threats Drop.", accent: "Traffic Pops.", color: "#0077ff" },
        { main: "Auto Denied.", accent: "Authentic Verified.", color: "#bd00ff" },
        { main: "Bad Actors Pay.", accent: "Real Users Play.", color: "#00ff88" },
        { main: "Entropy Scanned.", accent: "Security Manned.", color: "#ff3333" },
        { main: "Identity Known.", accent: "Friction Blown.", color: "#ffff00" },
        { main: "Proxies Drop.", accent: "Identity Prop.", color: "#00ffcc" }
    ];

    // Select based on session to keep it consistent for one visit if desired, 
    // but the user said "when user refresh or come back next time", so pure random is fine.
    const selected = variations[Math.floor(Math.random() * variations.length)];

    heroTitle.innerHTML = `${selected.main} <span style="color: ${selected.color}">${selected.accent}</span>`;
};

const setupAIAgent = () => {
    const agent = document.getElementById('sentinel-ai-agent');
    if (!agent) {
        // Create it dynamically if not in HTML (for existing pages)
        const div = document.createElement('div');
        div.id = 'sentinel-ai-agent';
        div.className = 'ai-sidebar';
        div.innerHTML = `
            <h4><span class="ai-status-dot"></span> Sentinel Intelligence</h4>
            <div class="ai-message" id="ai-dynamic-message">Initializing security agent... Scanning page context.</div>
            <hr style="border: 0; border-top: 1px solid #222; margin: 15px 0;">
            <div id="ai-agent-tips" style="font-size: 0.7rem; color: var(--text-dim);"></div>
        `;
        document.body.appendChild(div);
    }

    const msg = document.getElementById('ai-dynamic-message');
    const tips = document.getElementById('ai-agent-tips');

    const path = window.location.pathname;
    let contextMsg = "Monitoring global bot patterns. I've detected a significant rise in headless browser spoofing today.";
    let tipHtml = 'Ask me about: <span style="color: var(--accent); cursor: pointer;" onclick="window.askAI(\'bot patterns\')">Bot Patterns</span>';

    if (path.includes('stop-ai-bot-abuse')) {
        contextMsg = "I'm analyzing the 'Stop AI Bot Abuse' context. 92% of these bots originate from specific ASN ranges I can identify.";
        tipHtml = 'Ask me about: <span style="color: var(--accent); cursor: pointer;" onclick="window.askAI(\'ASN filtering\')">ASN Filtering</span>';
    } else if (path.includes('agentic-ai')) {
        contextMsg = "Agentic threats are evolving. I've logged 15 new 'Prompt Injection' signatures in the last hour.";
        tipHtml = 'Ask me about: <span style="color: var(--accent); cursor: pointer;" onclick="window.askAI(\'injection defense\')">Injection Defense</span>';
    }

    setTimeout(() => {
        if (msg) msg.innerText = contextMsg;
        if (tips) tips.innerHTML = tipHtml;
    }, 2000);

    window.askAI = (topic) => {
        if (msg) msg.innerText = `Synthesizing report on ${topic.toUpperCase()}... I have identified several mitigation layers in Sentinel's core that handle this automatically.`;
    };
};

document.addEventListener('DOMContentLoaded', () => {
    setupDynamicHero();
    technicalInit();
    setupDemoWidget();
    setupRiskDemo();
    setupUtils();
    setupScrollReveal();
    setupAIAgent();
});
