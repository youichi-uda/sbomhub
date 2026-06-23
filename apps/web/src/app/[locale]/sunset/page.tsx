import { getTranslations } from "next-intl/server";
import Link from "next/link";
import { ArrowLeft, ExternalLink, Github, Mail, Server } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { WaitlistForm } from "@/components/landing/WaitlistForm";

const GITHUB_URL = "https://github.com/youichi-uda/sbomhub";
const CONTACT_EMAIL = "hello@sbomhub.app";

interface Props {
  params: Promise<{ locale: string }>;
}

export default async function SunsetPage({ params }: Props) {
  const { locale } = await params;
  const t = await getTranslations({ locale, namespace: "Sunset" });

  return (
    <div className="min-h-screen bg-gradient-to-b from-amber-50 via-white to-white">
      <header className="border-b bg-white/80 backdrop-blur">
        <div className="container mx-auto flex items-center justify-between px-4 py-4">
          <Link href={`/${locale}`} className="text-2xl font-bold text-primary">
            SBOMHub
          </Link>
          <Link
            href={`/${locale}`}
            className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-4 w-4" />
            {t("backToTop")}
          </Link>
        </div>
      </header>

      <main className="container mx-auto max-w-4xl px-4 py-16">
        <div className="mb-12 text-center">
          <span className="inline-block rounded-full bg-amber-100 px-3 py-1 text-xs font-medium uppercase tracking-wide text-amber-800">
            SaaS Sunset
          </span>
          <h1 className="mt-4 text-3xl font-bold md:text-4xl">{t("title")}</h1>
          <p className="mt-4 text-lg text-muted-foreground">{t("subtitle")}</p>
        </div>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Server className="h-5 w-5 text-primary" />
                {t("selfHostTitle")}
              </CardTitle>
              <CardDescription>{t("selfHostDescription")}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <pre className="overflow-x-auto rounded-md border bg-gray-900 p-4 text-sm text-gray-100">
                <code>{`git clone https://github.com/youichi-uda/sbomhub.git
cd sbomhub
docker compose up -d
# -> http://localhost:3000`}</code>
              </pre>
              <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer">
                <Button variant="outline" className="gap-2">
                  <Github className="h-4 w-4" />
                  {t("repoCta")}
                  <ExternalLink className="h-3.5 w-3.5" />
                </Button>
              </a>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{t("waitlistTitle")}</CardTitle>
              <CardDescription>{t("waitlistDescription")}</CardDescription>
            </CardHeader>
            <CardContent>
              <WaitlistForm variant="section" />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Mail className="h-5 w-5 text-primary" />
                {t("existingTitle")}
              </CardTitle>
              <CardDescription>{t("existingDescription")}</CardDescription>
            </CardHeader>
            <CardContent>
              <a href={`mailto:${CONTACT_EMAIL}`}>
                <Button variant="default" className="gap-2">
                  <Mail className="h-4 w-4" />
                  {t("contactCta")}
                </Button>
              </a>
            </CardContent>
          </Card>
        </div>

        <p className="mt-12 text-center text-xs text-muted-foreground">
          {t("lastUpdated")}
        </p>
      </main>
    </div>
  );
}
