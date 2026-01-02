/**
 * dotsecenv version configuration
 *
 * Fetches the latest release version from GitHub at build time.
 * Falls back to a hardcoded version if the API is unavailable.
 */

const GITHUB_REPO = 'dotsecenv/dotsecenv';
const FALLBACK_VERSION = '0.2.1';

async function fetchLatestVersion(): Promise<string> {
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

// Fetch once at module load time (build time in Astro)
export const DOTSECENV_VERSION: Promise<string> = fetchLatestVersion();
