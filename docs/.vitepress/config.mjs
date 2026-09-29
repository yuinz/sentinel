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
  transformHead({ pageData }) {
    const canonical = docCanonical(pageData.relativePath)
    const desc = pageData.description || pageData.frontmatter?.description
    const head = [
      ['link', { rel: 'canonical', href: canonical }],
      ['meta', { name: 'robots', content: 'index, follow' }],
    ]
    if (desc) {
      head.push(['meta', { name: 'description', content: desc }])
      head.push(['meta', { property: 'og:description', content: desc }])
    }
    head.push(['meta', { property: 'og:title', content: `${pageData.title || 'Docs'} | Sentinel` }])
    head.push(['meta', { property: 'og:url', content: canonical }])
    head.push(['meta', { property: 'og:type', content: 'article' }])
    return head
  },
  themeConfig: {
    logo: 'https://vitepress.dev/vitepress-logo-mini.svg', 
    nav: [
      { text: 'Home', link: '/' },
      { text: 'V2 Docs', link: '/introduction' },
      { text: '← V1 Legacy Docs', link: 'https://sentinel.risksignal.name.ng/docs.html' }
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
      {
        text: 'Legacy',
        items: [
          { text: 'V1 product docs', link: 'https://sentinel.risksignal.name.ng/docs.html' }
        ]
      }
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
