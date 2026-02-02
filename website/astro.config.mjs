import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { SITE_TITLE } from './src/consts';

export default defineConfig({
  site: 'https://dotsecenv.com',
  integrations: [
    starlight({
      title: SITE_TITLE,
      routeMiddleware: ['./src/route-data'],
      logo: {
        src: './src/assets/logo.png',
        alt: 'logo',
      },
      favicon: '/favicon.png',
      tagline: 'Safe environment secrets',
      description: 'Secure secrets management CLI that encrypts environment variables at rest using GPG, making them safe to commit to version control.',

      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/dotsecenv/dotsecenv' },
        { icon: 'x.com', label: 'X', href: 'https://x.com/dotsecenv' },
      ],

      editLink: {
        baseUrl: 'https://github.com/dotsecenv/website/edit/main/',
      },

      disable404Route: true,

      customCss: [
        '@fontsource/inter/400.css',
        '@fontsource/inter/500.css',
        '@fontsource/inter/600.css',
        '@fontsource/jetbrains-mono/400.css',
        '@fontsource/jetbrains-mono/500.css',
        './src/styles/custom.css',
      ],

      head: [
        {
          tag: 'meta',
          attrs: {
            name: 'theme-color',
            content: '#0f0f0f',
          },
        },
        {
          tag: 'link',
          attrs: {
            rel: 'icon',
            href: '/favicon.png',
            sizes: '32x32',
            type: 'image/png',
          },
        },
        {
          tag: 'link',
          attrs: {
            rel: 'apple-touch-icon',
            href: '/apple-touch-icon.png',
            sizes: '180x180',
          },
        },
        {
          tag: 'link',
          attrs: {
            rel: 'icon',
            href: '/icon-192.png',
            sizes: '192x192',
            type: 'image/png',
          },
        },
      ],

      tableOfContents: {
        minHeadingLevel: 2,
        maxHeadingLevel: 3,
      },

      sidebar: [
        {
          label: 'Start Here',
          items: [
            { label: 'Introduction', slug: '' },
            { label: 'Getting Started', slug: 'getting-started' },
          ],
        },
        {
          label: 'Tutorials',
          items: [
            { label: 'Installation', slug: 'tutorials/installation' },
            { label: 'Your First Secret', slug: 'tutorials/first-secret' },
            { label: 'Share a Secret', slug: 'tutorials/share-secret' },
            { label: 'Revoke Access', slug: 'tutorials/revoke-access' },
          ],
        },
        {
          label: 'Concepts',
          items: [
            { label: 'Philosophy', slug: 'concepts/philosophy' },
            { label: 'Security Model', slug: 'concepts/security-model' },
            { label: 'Threat Model', slug: 'concepts/threat-model' },
            { label: 'Architecture', slug: 'concepts/architecture' },
            { label: 'Vault Format', slug: 'concepts/vault-format' },
            { label: 'Behavior Settings', slug: 'concepts/behavior-settings' },
            { label: 'Standards Compliance', slug: 'concepts/compliance' },
            { label: 'Comparison', slug: 'concepts/comparison' },
          ],
        },
        {
          label: 'Guides',
          items: [
            { label: 'Shell Plugins', slug: 'guides/shell-plugins' },
            { label: 'GitHub Action', slug: 'guides/github-action' },
            { label: 'How-To', slug: 'how-to' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'CLI Reference', slug: 'reference' },
            { label: 'Changelog', slug: 'changelog' },
          ],
        },
      ],

      lastUpdated: true,

      pagination: true,

      credits: false,
    }),
  ],
});
