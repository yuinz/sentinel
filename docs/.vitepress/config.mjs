import { defineConfig } from 'vitepress'

export default defineConfig({
  base: '/docs/',
  title: "Sentinel Engine",
  description: "B2B Dynamic Security Platform",
  themeConfig: {
    logo: 'https://vitepress.dev/vitepress-logo-mini.svg', 
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Docs', link: '/introduction' }
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
        text: 'V2 Architecture',
        items: [
          { text: 'Custom Policy DSL', link: '/dsl-rules' },
          { text: 'API Reference', link: '/v2-api' }
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
