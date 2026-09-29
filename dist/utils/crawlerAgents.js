"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isCrawlerUserAgent = isCrawlerUserAgent;
/** Known search, SEO, and social preview crawlers — do not rate-limit or treat as product traffic. */
const CRAWLER_UA = /googlebot|google-inspectiontool|storebot-google|apis-google|bingbot|applebot|duckduckbot|yandexbot|slurp|ahrefsbot|semrushbot|mj12bot|dotbot|rogerbot|facebot|facebookexternalhit|twitterbot|linkedinbot|slackbot|discordbot|pinterestbot|bytespider/i;
function isCrawlerUserAgent(userAgent) {
    return CRAWLER_UA.test(userAgent || '');
}
