import { defineConfig } from 'vitepress'

// 部署在 https://kulaiyin.github.io/go-cipher-cli/，需设置 base。
// 如部署到自定义域名根路径，将 base 改为 '/'。
export default defineConfig({
  lang: 'zh-CN',
  title: 'go-cipher-cli',
  description: '基于 Go 的 CLI 工具：配置管理、日志、交互提示、进度条，支持 APT 仓库分发',
  base: '/go-cipher-cli/',
  lastUpdated: true,
  cleanUrls: true,

  head: [
    ['meta', { name: 'theme-color', content: '#3c8772' }]
  ],

  themeConfig: {
    nav: [
      { text: '指南', link: '/guide/installation' },
      { text: '打包发布', link: '/guide/packaging' },
      { text: 'GitHub', link: 'https://github.com/kulaiyin/go-cipher-cli' }
    ],

    sidebar: [
      {
        text: '入门',
        items: [
          { text: '安装', link: '/guide/installation' },
          { text: '使用', link: '/guide/usage' }
        ]
      },
      {
        text: '密钥管理',
        items: [
          { text: '概述', link: '/guide/key-management' },
          { text: '需求说明', link: '/spec/key-management' }
        ]
      },
      {
        text: '打包与发布',
        items: [
          { text: '概述', link: '/guide/packaging' },
          { text: 'APT 仓库与 GitHub Pages', link: '/guide/apt-repo' },
          { text: 'CI/CD 流水线', link: '/guide/ci-cd' }
        ]
      }
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/kulaiyin/go-cipher-cli' }
    ],

    footer: {
      message: '基于 MIT 协议发布',
      copyright: 'Copyright © 2026 kulaiyin'
    },

    outline: {
      label: '本页目录'
    },

    docFooter: {
      prev: '上一页',
      next: '下一页'
    },

    lastUpdated: {
      text: '最后更新于'
    },

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
})
