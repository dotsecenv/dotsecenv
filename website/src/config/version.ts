/**
 * dotsecenv version configuration
 *
 * Priority:
 * 1. DOTSECENV_VERSION environment variable (if set)
 * 2. Fetches the latest release version from GitHub at build time
 * 3. Falls back to the agent plugin manifest's version if the API is unavailable
 */

// The release bump command (.releasetools.yaml) sets this version every
// release, so the fallback never goes stale like a hardcoded constant did.
import pluginManifest from '../../../.claude-plugin/plugin.json';

const GITHUB_REPO = 'dotsecenv/dotsecenv';
const FALLBACK_VERSION: string = pluginManifest.version;

async function getVersion(): Promise<string> {
  // Check for environment variable override first
  const envVersion = process.env.DOTSECENV_VERSION;
  if (envVersion && envVersion.trim() !== '') {
    const version = envVersion.trim().replace(/^v/, '');
    console.log(`Using dotsecenv version from environment: ${version}`);
    return version;
  }

  // Fetch from GitHub API
  try {
    const response = await fetch(
      `https://api.github.com/repos/${GITHUB_REPO}/releases/latest`,
      {
        headers: {
          Accept: 'application/vnd.github.v3+json',
          // Use token if available (for higher rate limits in CI)
          ...(process.env.GITHUB_TOKEN && {
            Authorization: `token ${process.env.GITHUB_TOKEN}`,
          }),
        },
      }
    );

    if (!response.ok) {
      console.warn(
        `Failed to fetch latest version from GitHub (${response.status}), using fallback`
      );
      return FALLBACK_VERSION;
    }

    const data = await response.json();
    const version = data.tag_name?.replace(/^v/, '') || FALLBACK_VERSION;
    console.log(`Fetched dotsecenv version from GitHub: ${version}`);
    return version;
  } catch (error) {
    console.warn(`Error fetching version from GitHub: ${error}, using fallback`);
    return FALLBACK_VERSION;
  }
}

// Resolve version once at module load time (build time in Astro)
export const DOTSECENV_VERSION: Promise<string> = getVersion();
