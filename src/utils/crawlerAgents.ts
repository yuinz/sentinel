/** Known search, SEO, and social preview crawlers — do not rate-limit or treat as product traffic. */
const CRAWLER_UA =
    /googlebot|google-inspectiontool|storebot-google|apis-google|bingbot|applebot|duckduckbot|yandexbot|slurp|ahrefsbot|semrushbot|mj12bot|dotbot|rogerbot|facebot|facebookexternalhit|twitterbot|linkedinbot|slackbot|discordbot|pinterestbot|bytespider/i;

export function isCrawlerUserAgent(userAgent: string | undefined): boolean {
    return CRAWLER_UA.test(userAgent || '');
}
