import { getTranslations } from "next-intl/server";
import Link from "next/link";
import { AlertTriangle, ArrowRight, Github, Mail } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

const GITHUB_URL = "https://github.com/youichi-uda/sbomhub";
const CONTACT_EMAIL = "hello@sbomhub.app";

interface Props {
  params: Promise<{ locale: string }>;
}

/**
 * Sign-up is closed while the SaaS is sunset.
 * This page replaces the Clerk SignUp widget with a sunset notice and
 * routes users to the public sunset page / self-host docs / waitlist.
 */
export default async function SignUpPage({ params }: Props) {
  const { locale } = await params;
  const t = await getTranslations({ locale, namespace: "Sunset" });

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4 py-12">
      <Card className="w-full max-w-xl border-amber-200 shadow-lg">
        <CardHeader>
          <div className="mb-2 flex items-center gap-2 text-amber-700">
            <AlertTriangle className="h-5 w-5" />
            <span className="text-xs font-semibold uppercase tracking-wide">
              SaaS Sunset
            </span>
          </div>
          <CardTitle className="text-2xl">{t("title")}</CardTitle>
          <CardDescription className="pt-2">{t("subtitle")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 text-sm text-muted-foreground">
          <p>{t("selfHostDescription")}</p>
          <p>{t("existingDescription")}</p>
          <div className="flex flex-col gap-2 pt-2 sm:flex-row">
            <Link href={`/${locale}/sunset`} className="w-full sm:w-auto">
              <Button className="w-full gap-2">
                {t("viewDetailsCta")}
                <ArrowRight className="h-4 w-4" />
              </Button>
            </Link>
            <a
              href={GITHUB_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="w-full sm:w-auto"
            >
              <Button variant="outline" className="w-full gap-2">
                <Github className="h-4 w-4" />
                {t("repoCta")}
              </Button>
            </a>
            <a href={`mailto:${CONTACT_EMAIL}`} className="w-full sm:w-auto">
              <Button variant="ghost" className="w-full gap-2">
                <Mail className="h-4 w-4" />
                {t("contactCta")}
              </Button>
            </a>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
