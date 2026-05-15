// Per-page raw-markdown endpoint.
//
// Serves the raw markdown body of every entry in the `docs` content collection
// under a `.md` URL alongside the rendered HTML page. This is what AI coding
// agents (Claude Code, Cursor, etc.) and contextual-menu integrations consume
// when a user asks "fetch this page as markdown".
//
// URL convention:
//   /getting-started/                 → /getting-started.md
//   /tutorials/installation/          → /tutorials/installation.md
//   /                                 → /index.md
//   /concepts/security-model/         → /concepts/security-model.md
//
// The root index is served at `/index.md` (rather than `/.md`) because the
// rest-parameter `[...slug]` would collapse the empty path to a route file
// name `.md` — `index` is the conventional and predictable choice.
//
// For MDX entries we emit `entry.body` verbatim. Imports and component tags
// (e.g. `<Tabs>`, `<Card>`) survive in the output. That is acceptable noise
// for LLM consumption — readers strip JSX easily, and the prose, headings,
// and code blocks (the load-bearing content) are preserved exactly as
// authored. A future iteration can post-process via `starlight-llms-txt`'s
// markdown helpers if we want a cleaner stripped form.

import type { APIRoute, GetStaticPaths } from 'astro';
import { getCollection } from 'astro:content';

export const getStaticPaths = (async () => {
  const entries = await getCollection('docs');
  return entries.map((entry) => ({
    // Empty id is the root `index.mdx`; expose it as `/index.md`.
    params: { slug: entry.id === '' ? 'index' : entry.id },
    props: { body: entry.body ?? '', id: entry.id },
  }));
}) satisfies GetStaticPaths;

export const GET: APIRoute = ({ props }) => {
  const { body } = props as { body: string; id: string };
  return new Response(body, {
    headers: {
      'Content-Type': 'text/markdown; charset=utf-8',
      // Encourage caches to revalidate but allow short-term reuse by agents.
      'Cache-Control': 'public, max-age=300, must-revalidate',
    },
  });
};
