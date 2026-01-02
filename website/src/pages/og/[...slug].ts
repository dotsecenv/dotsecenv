import { getCollection } from 'astro:content';
import { OGImageRoute } from 'astro-og-canvas';

const entries = await getCollection('docs');

const pages = Object.fromEntries(
  entries.map(({ id, data }) => [id, { data }])
);

export const { getStaticPaths, GET } = OGImageRoute({
  param: 'slug',
  pages,
  getImageOptions: (_path, page: (typeof pages)[string]) => ({
    title: page.data.title,
    description: page.data.description,
    logo: {
      path: './src/assets/logo.png',
      size: [100],
    },
    bgGradient: [[15, 15, 15]],
    border: {
      color: [66, 162, 106],
      width: 20,
      side: 'inline-start',
    },
    font: {
      title: {
        color: [229, 229, 229],
        families: ['Inter'],
        weight: 'SemiBold',
        size: 72,
      },
      description: {
        color: [163, 163, 163],
        families: ['Inter'],
        size: 36,
      },
    },
    fonts: [
      'https://cdn.jsdelivr.net/fontsource/fonts/inter@latest/latin-400-normal.woff2',
      'https://cdn.jsdelivr.net/fontsource/fonts/inter@latest/latin-600-normal.woff2',
    ],
  }),
});
