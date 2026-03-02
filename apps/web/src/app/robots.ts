import { MetadataRoute } from "next";

const BASE_URL = process.env.NEXT_PUBLIC_BASE_URL || "https://sbomhub.com";

export default function robots(): MetadataRoute.Robots & { host?: string } {
  return {
    rules: [
      {
        userAgent: "*",
        allow: "/",
        disallow: [
          "/api/",
          "/dashboard/",
          "/projects/",
          "/settings/",
          "/sign-in/",
          "/sign-up/",
        ],
      },
      {
        userAgent: "GPTBot",
        allow: ["/", "/llms.txt", "/llms-full.txt"],
        disallow: [
          "/api/",
          "/dashboard/",
          "/projects/",
          "/settings/",
          "/sign-in/",
          "/sign-up/",
        ],
      },
      {
        userAgent: "ChatGPT-User",
        allow: ["/", "/llms.txt", "/llms-full.txt"],
        disallow: [
          "/api/",
          "/dashboard/",
          "/projects/",
          "/settings/",
          "/sign-in/",
          "/sign-up/",
        ],
      },
      {
        userAgent: "Claude-Web",
        allow: ["/", "/llms.txt", "/llms-full.txt"],
        disallow: [
          "/api/",
          "/dashboard/",
          "/projects/",
          "/settings/",
          "/sign-in/",
          "/sign-up/",
        ],
      },
      {
        userAgent: "PerplexityBot",
        allow: ["/", "/llms.txt", "/llms-full.txt"],
        disallow: [
          "/api/",
          "/dashboard/",
          "/projects/",
          "/settings/",
          "/sign-in/",
          "/sign-up/",
        ],
      },
      {
        userAgent: "CCBot",
        allow: ["/", "/llms.txt", "/llms-full.txt"],
        disallow: [
          "/api/",
          "/dashboard/",
          "/projects/",
          "/settings/",
          "/sign-in/",
          "/sign-up/",
        ],
      },
    ],
    sitemap: `${BASE_URL}/sitemap.xml`,
  };
}
