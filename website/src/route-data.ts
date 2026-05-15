import type { StarlightRouteData } from '@astrojs/starlight/route-data';
import { defineRouteMiddleware } from '@astrojs/starlight/route-data';

export const onRequest = defineRouteMiddleware((context) => {
  const route = context.locals.starlightRoute;
  if (!route) {
    return;
  }

  const ogImageUrl = getOgImageUrl(route);

  // Add og:image
  route.head.push({
    tag: 'meta',
    attrs: { property: 'og:image', content: ogImageUrl },
  });

  // Add og:image dimensions
  route.head.push({
    tag: 'meta',
    attrs: { property: 'og:image:width', content: '1200' },
  });

  route.head.push({
    tag: 'meta',
    attrs: { property: 'og:image:height', content: '630' },
  });

  // Add twitter:image
  route.head.push({
    tag: 'meta',
    attrs: { name: 'twitter:image', content: ogImageUrl },
  });
});

function getOgImageUrl(route: StarlightRouteData): string {
  const siteUrl = 'https://dotsecenv.com';
  if (!route.id) {
    return `${siteUrl}/og/index.png`;
  }
  // Remove file extension (.md, .mdx) from the id
  const slug = route.id.replace(/\.(md|mdx)$/, '');
  return `${siteUrl}/og/${slug === '' ? 'index' : slug}.png`;
}
