import { defineConfig } from 'vitepress'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

// 部署在 https://kulaiyin.github.io/go-cipher-cli/，需设置 base。
// 如部署到自定义域名根路径，将 base 改为 '/'。

// 读取版本号：CI 发版时由 release.yml 从 git tag 写入 version.json；
// 本地开发时为占位版本（0.0.0-dev）。
const __dirname = dirname(fileURLToPath(import.meta.url))
let siteVersion = '0.0.0-dev'
try {
  const v = JSON.parse(readFileSync(resolve(__dirname, 'version.json'), 'utf-8'))
  if (v && typeof v.version === 'string') siteVersion = v.version
} catch {
  // version.json 缺失时回退到占位版本
}

// 英文为主语言（根路径默认），中文为镜像语言
const enNav = [
  { text: 'Guide', link: '/en/guide/installation' },
  { text: 'Packaging', link: '/en/guide/packaging' },
  { text: 'GitHub', link: 'https://github.com/kulaiyin/go-cipher-cli' },
  // 版本号显示在导航栏右侧，点击跳转到 Releases 页面
  { text: `v${siteVersion}`, link: 'https://github.com/kulaiyin/go-cipher-cli/releases' }
]

const zhNav = [
  { text: '指南', link: '/zh/guide/installation' },
  { text: '打包发布', link: '/zh/guide/packaging' },
  { text: 'GitHub', link: 'https://github.com/kulaiyin/go-cipher-cli' },
  // 版本号显示在导航栏右侧，点击跳转到 Releases 页面
  { text: `v${siteVersion}`, link: 'https://github.com/kulaiyin/go-cipher-cli/releases' }
]

const enSidebar = [
  {
    text: 'Getting Started',
    items: [
      { text: 'Installation', link: '/en/guide/installation' },
      { text: 'Usage', link: '/en/guide/usage' }
    ]
  },
  {
    text: 'Key Management',
    items: [
      { text: 'Overview', link: '/en/guide/key-management' },
      { text: 'Specification', link: '/en/spec/key-management' }
    ]
  },
  {
    text: 'Packaging & Release',
    items: [
      { text: 'Overview', link: '/en/guide/packaging' },
      { text: 'APT Repository & GitHub Pages', link: '/en/guide/apt-repo' },
      { text: 'CI/CD Pipeline', link: '/en/guide/ci-cd' }
    ]
  }
]

const zhSidebar = [
  {
    text: '入门',
    items: [
      { text: '安装', link: '/zh/guide/installation' },
      { text: '使用', link: '/zh/guide/usage' }
    ]
  },
  {
    text: '密钥管理',
    items: [
      { text: '概述', link: '/zh/guide/key-management' },
      { text: '需求说明', link: '/zh/spec/key-management' }
    ]
  },
  {
    text: '打包与发布',
    items: [
      { text: '概述', link: '/zh/guide/packaging' },
      { text: 'APT 仓库与 GitHub Pages', link: '/zh/guide/apt-repo' },
      { text: 'CI/CD 流水线', link: '/zh/guide/ci-cd' }
    ]
  }
]

export default defineConfig({
  base: '/go-cipher-cli/',
  lastUpdated: true,
  cleanUrls: true,

  head: [
    ['meta', { name: 'theme-color', content: '#3c8772' }]
  ],

  locales: {
    root: {
      // 根路径为英文主语言
      label: 'English',
      lang: 'en',
      link: '/en/',
      themeConfig: {
        nav: enNav,
        sidebar: enSidebar,
        outline: { label: 'On this page' },
        docFooter: { prev: 'Previous', next: 'Next' },
        lastUpdated: { text: 'Last updated' },
        search: {
          provider: 'local',
          options: {
            translations: {
              button: {
                buttonText: 'Search',
                buttonAriaLabel: 'Search'
              },
              modal: {
                noResultsText: 'No results found',
                footer: {
                  selectText: 'Select',
                  navigateText: 'Switch'
                }
              }
            }
          }
        }
      }
    },
    zh: {
      label: '简体中文',
      lang: 'zh-CN',
      link: '/zh/',
      themeConfig: {
        nav: zhNav,
        sidebar: zhSidebar,
        outline: { label: '本页目录' },
        docFooter: { prev: '上一页', next: '下一页' },
        lastUpdated: { text: '最后更新于' },
        search: {
          provider: 'local',
          options: {
            translations: {
              button: {
                buttonText: '搜索文档',
                buttonAriaLabel: '搜索文档'
              },
              modal: {
                noResultsText: '无法找到相关结果',
                footer: {
                  selectText: '选择',
                  navigateText: '切换'
                }
              }
            }
          }
        }
      }
    }
  },

  themeConfig: {
    socialLinks: [
      { icon: 'github', link: 'https://github.com/kulaiyin/go-cipher-cli' }
    ],

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2026 kulaiyin'
    }
  }
})
