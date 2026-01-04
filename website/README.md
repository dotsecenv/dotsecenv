# dotsecenv website

[![Publish Website](https://github.com/dotsecenv/website/actions/workflows/deploy-website.yml/badge.svg)](https://github.com/dotsecenv/website/actions/workflows/deploy-website.yml)

This is [dotsecenv](https://github.com/dotsecenv/dotsecenv)'s project website, built with [Astro Starlight](https://starlight.astro.build/).

## Development

### Prerequisites

- Node.js 18+ or 20+
- pnpm (recommended) or npm

### Setup

```bash
# Install dependencies
pnpm install

# Start development server
pnpm dev
```

The site will be available at `http://localhost:4321`.

### Build

```bash
# Build for production
pnpm build

# Preview production build
pnpm preview
```

## Adding Content

### New Page

Create an MDX file in `src/content/docs/`:

```mdx
---
title: Page Title
description: Short description for SEO
---

Your content here...
```

### Sidebar

Update the sidebar in `astro.config.mjs`:

```js
sidebar: [
  {
    label: 'Section Name',
    items: [
      { label: 'Page Title', slug: 'page-slug' },
    ],
  },
],
```

## Customization

### Styling

Edit `src/styles/custom.css` for:

- Colors and theme
- Typography
- Spacing and layout

### Components

Starlight provides built-in components:

```mdx
import { Tabs, TabItem, Card, CardGrid, Aside, Steps } from '@astrojs/starlight/components';

<Tabs>
  <TabItem label="Tab 1">Content 1</TabItem>
  <TabItem label="Tab 2">Content 2</TabItem>
</Tabs>

<Aside type="tip">
  A helpful tip!
</Aside>
```

## Deployment

Build the static site:

```bash
pnpm build
```

The output is in the `dist/` directory. Deploy to any static hosting:

- GitHub Pages
- Vercel
- Netlify
- Cloudflare Pages

## License

APACHE 2.0 - See [LICENSE](./LICENSE) for details.
