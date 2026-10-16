import { defineConfig } from 'vitepress'

const SITE = 'https://sentinel.risksignal.name.ng'

function docCanonical(relativePath) {
  if (relativePath === 'index.md') return `${SITE}/docs/`
  return `${SITE}/docs/${relativePath.replace(/\.md$/, '.html')}`
}

export default defineConfig({
  base: '/docs/',
  title: 'Sentinel Documentation',
  description: 'Integrate Sentinel: /v2/evaluate, global policy, widgets, and where enforcement applies on your routes.',
  transformHead(ctx) {
    // VitePress 1.6.4 identifies the generated 404 as page "404.md".
    // Return before any canonical so this file is not an indexable URL.
    if (ctx.page === '404.md') {
      return [['meta', { name: 'robots', content: 'noindex' }]]
    }
    const canonical = docCanonical(ctx.pageData.relativePath)
    return [
      ['link', { rel: 'canonical', href: canonical }],
      ['meta', { property: 'og:title', content: ctx.title }],
      ['meta', { property: 'og:description', content: ctx.description }],
      ['meta', { property: 'og:url', content: canonical }],
      ['meta', { property: 'og:type', content: ctx.page === 'index.md' ? 'website' : 'article' }],
    ]
  },
  themeConfig: {
    logo: 'https://vitepress.dev/vitepress-logo-mini.svg', 
    nav: [
      { text: 'Home', link: '/' },
      { text: 'V2 Docs', link: '/introduction' }
    ],
    sidebar: [
      {
        text: 'Getting Started',
        items: [
          { text: 'Introduction', link: '/introduction' },
          { text: 'V1 vs V2', link: '/v1-vs-v2' }
        ]
      },
      {
        text: 'Guides',
        items: [
          { text: 'Where Sentinel applies', link: '/enforcement' }
        ]
      },
      {
        text: 'V2 Reference',
        items: [
          { text: 'Global Master Policies', link: '/dsl-rules' },
          { text: 'API Reference', link: '/v2-api' }
        ]
      },
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/yuinz/sentinel' }
    ],
    footer: {
      message: 'Enterprise Zero-Trust Shield.',
      copyright: 'Copyright © Sentinel Engine V2'
    }
  }
})
