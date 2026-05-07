import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightBlog from 'starlight-blog';
import starlightContextualMenu from 'starlight-contextual-menu';
import starlightLlmsTxt from 'starlight-llms-txt';
import { SITE_TITLE } from './src/consts';

export default defineConfig({
  site: 'https://dotsecenv.com',
  redirects: {
    // Renamed from Policy Directory → Security Policies (May 2026).
    // Preserve external links from blog posts, social shares, and search engines.
    '/concepts/policy-directory': '/concepts/security-policies/',
    '/concepts/policy-directory/': '/concepts/security-policies/',
  },
  integrations: [
    starlight({
      plugins: [
        starlightBlog({
          authors: {
            dotsecenv: {
              name: 'dotsecenv',
              title: 'Maintainer',
              picture: '/favicon.png',
              url: 'https://dotsecenv.com',
            },
          },
        }),
        starlightLlmsTxt({
          projectName: 'dotsecenv',
          description:
            'Secure secrets management CLI that encrypts environment variables at rest using GPG, making them safe to commit to version control.',
          details:
            'dotsecenv encrypts environment variables at rest using GPG and AES-256-GCM, storing them in vault files that are safe to commit to git. Documentation follows the Diataxis framework: Tutorials walk through tasks, Concepts explain the security model and architecture, Guides cover integrations (shell plugins, GitHub Actions, Terraform, Claude Code), and Reference documents the CLI surface.',
          // Surface index, getting-started, and the CLI reference at the top of llms.txt.
          promote: ['index*', 'getting-started*', 'reference*'],
          // Keep the blog out of the small/full bundles to save context budget.
          exclude: ['blog/**', 'privacy*'],
          // Diataxis grouping: emit one llms-<set>.txt per category, listed in llms.txt.
          customSets: [
            {
              label: 'Tutorials',
              description:
                'Task-oriented walkthroughs: install, first secret, sharing, revocation, CI/CD, migration from .env.',
              paths: ['tutorials/**'],
            },
            {
              label: 'Concepts',
              description:
                'Explanations of the security model, threat model, architecture, vault format, and compliance posture.',
              paths: ['concepts/**'],
            },
            {
              label: 'Guides',
              description:
                'Integration guides: shell plugins, GitHub Action, Terraform credentials helper, Claude Code, plus the how-to recipe book.',
              paths: ['guides/**', 'how-to'],
            },
            {
              label: 'Reference',
              description:
                'CLI reference and changelog.',
              paths: ['reference', 'changelog'],
            },
          ],
        }),
        // Per-page dropdown ("Copy page", "View as Markdown", "Open in
        // ChatGPT", "Open in Claude") next to the page title. The plugin
        // fetches `<page>/index.md` for copy/view actions and, with
        // `injectMarkdownRoutes: true` (default), auto-emits those routes
        // via its bundled `starlight-markdown` integration. PR #136 ships a
        // separate `<page>.md` endpoint for direct LLM/RAG consumption;
        // both URL conventions coexist intentionally.
        starlightContextualMenu({
          actions: ['copy', 'view', 'chatgpt', 'claude'],
        }),
      ],
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

      components: {
        Footer: './src/components/Footer.astro',
      },

      tableOfContents: {
        minHeadingLevel: 2,
        maxHeadingLevel: 4,
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
            { label: 'Reloading Secrets', slug: 'tutorials/reload-secrets' },
            { label: 'Migrate from .env', slug: 'tutorials/migrate-from-dotenv' },
            { label: 'Team Vault Setup', slug: 'tutorials/team-vault-setup' },
            { label: 'Team Onboarding', slug: 'tutorials/team-onboarding' },
            { label: 'CI/CD Secrets', slug: 'tutorials/ci-cd-secrets' },
            { label: 'Share a Secret', slug: 'tutorials/share-secret' },
            { label: 'Revoke Access', slug: 'tutorials/revoke-access' },
            { label: 'Installation Reference', slug: 'tutorials/installation' },
            { label: 'Your First Secret', slug: 'tutorials/first-secret' },
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
            { label: 'Audit Trail', slug: 'concepts/audit-trail' },
            { label: 'Behavior Settings', slug: 'concepts/behavior-settings' },
            { label: 'Security Policies', slug: 'concepts/security-policies' },
            { label: 'Standards Compliance', slug: 'concepts/compliance' },
            { label: 'Comparison', slug: 'concepts/comparison' },
          ],
        },
        {
          label: 'Guides',
          items: [
            { label: 'Shell Plugins', slug: 'guides/shell-plugins' },
            { label: 'GitHub Action', slug: 'guides/github-action' },
            { label: 'Terraform & OpenTofu', slug: 'guides/terraform-credentials-helper' },
            { label: 'Claude Code', slug: 'guides/claude-code' },
            { label: 'GPG Agent', slug: 'guides/gpg-agent' },
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
