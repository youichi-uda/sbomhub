import { MetadataRoute } from "next";

const BASE_URL = process.env.NEXT_PUBLIC_BASE_URL || "https://sbomhub.com";

const locales = ["ja", "en"];

export default function sitemap(): MetadataRoute.Sitemap {
  const routes = [
    "",
    "/privacy",
    "/terms",
    "/legal",
  ];

  const sitemap: MetadataRoute.Sitemap = [];

  for (const locale of locales) {
    for (const route of routes) {
      sitemap.push({
        url: `${BASE_URL}/${locale}${route}`,
        lastModified: new Date(),
        changeFrequency: route === "" ? "weekly" : "monthly",
        priority: route === "" ? 1.0 : 0.5,
        alternates: {
          languages: {
            ja: `${BASE_URL}/ja${route}`,
            en: `${BASE_URL}/en${route}`,
          },
        },
      });
    }
  }

  return sitemap;
}
