/**
 * Builds landing-page/sitemap.xml from public HTML + VitePress dist.
 * Run after docs:build — npm run seo:sitemap
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const SITE = 'https://sentinel.risksignal.name.ng';
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const LANDING = path.join(ROOT, 'landing-page');
const DOCS_DIST = path.join(ROOT, 'docs', '.vitepress', 'dist');

const EXCLUDE_FILES = new Set([
    'login.html',
    'app.html',
    'dashboard.html',
    'widget-test.html',
    'test.html',
    'test-v1.html',
    'docs.html',
    '404.html',
]);

const EXCLUDE_DIRS = ['sentinel-ui-reference'];

function collectLandingUrls(dir, relDir = '') {
    const out = [];
    if (!fs.existsSync(dir)) return out;
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        const rel = relDir ? `${relDir}/${ent.name}` : ent.name;
        if (ent.isDirectory()) {
            if (EXCLUDE_DIRS.some((d) => rel === d || rel.startsWith(`${d}/`))) continue;
            out.push(...collectLandingUrls(path.join(dir, ent.name), rel));
            continue;
        }
        if (!ent.name.endsWith('.html') || EXCLUDE_FILES.has(ent.name)) continue;
        if (rel === 'index.html') {
            out.push(`${SITE}/`);
        } else {
            out.push(`${SITE}/${rel}`);
        }
    }
    return out;
}

function collectDocsUrls() {
    const out = [];
    if (!fs.existsSync(DOCS_DIST)) {
        console.warn('warn: docs dist missing — run npm run docs:build first');
        return out;
    }
    for (const ent of fs.readdirSync(DOCS_DIST, { withFileTypes: true })) {
        if (!ent.isFile() || !ent.name.endsWith('.html') || ent.name === '404.html') continue;
        if (ent.name === 'index.html') {
            out.push(`${SITE}/docs/`);
        } else {
            out.push(`${SITE}/docs/${ent.name}`);
        }
    }
    return out;
}

function priority(loc) {
    if (loc === `${SITE}/`) return '1.0';
    if (loc.includes('/docs/introduction.html') || loc === `${SITE}/docs/`) return '0.9';
    if (loc.includes('/docs/')) return '0.85';
    if (loc.endsWith('/blog.html') || loc.endsWith('/about.html')) return '0.8';
    if (loc.includes('/privacy.html') || loc.includes('/terms.html')) return '0.3';
    return '0.65';
}

const lastmod = new Date().toISOString().slice(0, 10);
const urls = [...new Set([...collectLandingUrls(LANDING), ...collectDocsUrls()])].sort();

const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls
    .map(
        (loc) => `  <url>
    <loc>${loc}</loc>
    <lastmod>${lastmod}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>${priority(loc)}</priority>
  </url>`
    )
    .join('\n')}
</urlset>
`;

const outPath = path.join(LANDING, 'sitemap.xml');
fs.writeFileSync(outPath, xml, 'utf8');
console.log(`wrote ${urls.length} urls → ${outPath}`);
