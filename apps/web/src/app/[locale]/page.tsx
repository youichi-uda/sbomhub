import { getTranslations } from "next-intl/server";
import Link from "next/link";
import Script from "next/script";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Shield,
  FileSearch,
  AlertTriangle,
  GitBranch,
  BarChart3,
  Globe,
  Check,
  ArrowRight,
  Building2,
  GitCompare,
  Scale,
} from "lucide-react";

const BASE_URL = process.env.NEXT_PUBLIC_BASE_URL || "https://sbomhub.com";

interface Props {
  params: Promise<{ locale: string }>;
}

function generateJsonLd(locale: string) {
  return {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "WebSite",
        "@id": `${BASE_URL}/#website`,
        url: BASE_URL,
        name: "SBOMHub",
        description:
          locale === "ja"
            ? "オープンソースのSBOM管理プラットフォーム"
            : "Open-source SBOM management platform",
        inLanguage: locale === "ja" ? "ja-JP" : "en-US",
      },
      {
        "@type": "SoftwareApplication",
        "@id": `${BASE_URL}/#software`,
        name: "SBOMHub",
        applicationCategory: "SecurityApplication",
        operatingSystem: "Web-based",
        description:
          locale === "ja"
            ? "CycloneDX/SPDXのインポート、脆弱性管理、VEXステートメント作成、コンプライアンスチェックを提供するSBOM管理プラットフォーム"
            : "SBOM management platform providing CycloneDX/SPDX import, vulnerability management, VEX statement creation, and compliance checking",
        url: BASE_URL,
        offers: [
          {
            "@type": "Offer",
            name: "Self-hosted",
            price: "0",
            priceCurrency: "JPY",
            description:
              locale === "ja" ? "無料のセルフホスト版" : "Free self-hosted version",
          },
          {
            "@type": "Offer",
            name: "Cloud Starter",
            price: "2500",
            priceCurrency: "JPY",
            description:
              locale === "ja"
                ? "小規模チーム向けクラウド版"
                : "Cloud version for small teams",
          },
          {
            "@type": "Offer",
            name: "Cloud Pro",
            price: "8000",
            priceCurrency: "JPY",
            description:
              locale === "ja"
                ? "成長するチーム向けフル機能版"
                : "Full-featured version for growing teams",
          },
        ],
        featureList: [
          "SBOM Import (CycloneDX, SPDX)",
          "Vulnerability Management",
          "VEX Statements",
          "Compliance Checking",
          "CI/CD Integration",
          "IPA Integration",
          "SBOM Diff Comparison",
          "Multilingual Support (Japanese/English)",
        ],
      },
      {
        "@type": "Organization",
        "@id": `${BASE_URL}/#organization`,
        name: "SBOMHub",
        url: BASE_URL,
        logo: `${BASE_URL}/logo.png`,
        sameAs: ["https://github.com/youichi-uda/sbomhub"],
      },
    ],
  };
}

export default async function LandingPage({ params }: Props) {
  const { locale } = await params;
  const t = await getTranslations("Landing");

  const features = [
    {
      icon: FileSearch,
      title: t("features.import.title"),
      description: t("features.import.description"),
    },
    {
      icon: AlertTriangle,
      title: t("features.vulnerability.title"),
      description: t("features.vulnerability.description"),
    },
    {
      icon: Shield,
      title: t("features.vex.title"),
      description: t("features.vex.description"),
    },
    {
      icon: BarChart3,
      title: t("features.compliance.title"),
      description: t("features.compliance.description"),
    },
    {
      icon: Scale,
      title: t("features.license.title"),
      description: t("features.license.description"),
    },
    {
      icon: GitBranch,
      title: t("features.cicd.title"),
      description: t("features.cicd.description"),
    },
    {
      icon: Building2,
      title: t("features.ipa.title"),
      description: t("features.ipa.description"),
    },
    {
      icon: GitCompare,
      title: t("features.diff.title"),
      description: t("features.diff.description"),
    },
    {
      icon: Globe,
      title: t("features.i18n.title"),
      description: t("features.i18n.description"),
    },
  ];

  const plans = [
    {
      name: t("pricing.free.name"),
      price: t("pricing.free.price"),
      period: "",
      description: t("pricing.free.description"),
      features: [
        t("pricing.free.feature1"),
        t("pricing.free.feature2"),
        t("pricing.free.feature3"),
        t("pricing.free.feature4"),
        t("pricing.free.feature5"),
      ],
      cta: t("pricing.free.cta"),
      href: "https://github.com/youichi-uda/sbomhub",
      highlight: false,
    },
    {
      name: t("pricing.starter.name"),
      price: t("pricing.starter.price"),
      period: t("pricing.starter.period"),
      description: t("pricing.starter.description"),
      features: [
        t("pricing.starter.feature1"),
        t("pricing.starter.feature2"),
        t("pricing.starter.feature3"),
        t("pricing.starter.feature4"),
        t("pricing.starter.feature5"),
      ],
      cta: t("pricing.starter.cta"),
      href: `/${locale}/sign-up`,
      highlight: true,
    },
    {
      name: t("pricing.pro.name"),
      price: t("pricing.pro.price"),
      period: t("pricing.pro.period"),
      description: t("pricing.pro.description"),
      features: [
        t("pricing.pro.feature1"),
        t("pricing.pro.feature2"),
        t("pricing.pro.feature3"),
        t("pricing.pro.feature4"),
      ],
      cta: t("pricing.pro.cta"),
      href: `/${locale}/sign-up`,
      highlight: false,
    },
    {
      name: t("pricing.team.name"),
      price: t("pricing.team.price"),
      period: t("pricing.team.period"),
      description: t("pricing.team.description"),
      features: [
        t("pricing.team.feature1"),
        t("pricing.team.feature2"),
        t("pricing.team.feature3"),
        t("pricing.team.feature4"),
      ],
      cta: t("pricing.team.cta"),
      href: `/${locale}/sign-up`,
      highlight: false,
    },
  ];

  const jsonLd = generateJsonLd(locale);

  return (
    <>
      <Script
        id="json-ld"
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
      <div className="min-h-screen flex flex-col">
        {/* Header */}
      <header className="border-b bg-white">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <Link href="/" className="text-2xl font-bold text-primary">
            SBOMHub
          </Link>
          <nav className="flex items-center gap-6">
            <Link href="#features" className="text-sm text-muted-foreground hover:text-foreground">
              {t("nav.features")}
            </Link>
            <Link href="#pricing" className="text-sm text-muted-foreground hover:text-foreground">
              {t("nav.pricing")}
            </Link>
            <div className="flex items-center gap-2">
              <Link href={`/${locale}/sign-in`}>
                <Button variant="ghost" size="sm">{t("nav.signIn")}</Button>
              </Link>
              <Link href={`/${locale}/sign-up`}>
                <Button size="sm">{t("nav.getStarted")}</Button>
              </Link>
            </div>
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1">
        {/* Hero Section */}
        <section className="py-20 bg-gradient-to-b from-blue-50 to-white">
          <div className="container mx-auto px-4 text-center">
            <Badge variant="secondary" className="mb-4">
              {t("hero.badge")}
            </Badge>
            <h1 className="text-4xl md:text-6xl font-bold mb-6 bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
              {t("hero.title")}
            </h1>
            <p className="text-xl text-muted-foreground mb-8 max-w-2xl mx-auto">
              {t("hero.description")}
            </p>
            <div className="flex gap-4 justify-center">
              <Link href={`/${locale}/sign-up`}>
                <Button size="lg" className="gap-2">
                  {t("hero.cta")}
                  <ArrowRight className="h-4 w-4" />
                </Button>
              </Link>
              <a href="https://github.com/youichi-uda/sbomhub" target="_blank" rel="noopener noreferrer">
                <Button size="lg" variant="outline">
                  {t("hero.github")}
                </Button>
              </a>
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section id="features" className="py-20">
          <div className="container mx-auto px-4">
            <div className="text-center mb-12">
              <h2 className="text-3xl font-bold mb-4">{t("features.title")}</h2>
              <p className="text-muted-foreground max-w-2xl mx-auto">
                {t("features.description")}
              </p>
            </div>
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
              {features.map((feature, index) => (
                <Card key={index} className="border-2 hover:border-primary/50 transition-colors">
                  <CardHeader>
                    <feature.icon className="h-10 w-10 text-primary mb-2" />
                    <CardTitle className="text-lg">{feature.title}</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <CardDescription>{feature.description}</CardDescription>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </section>

        {/* Pricing Section */}
        <section id="pricing" className="py-20 bg-gray-50">
          <div className="container mx-auto px-4">
            <div className="text-center mb-12">
              <h2 className="text-3xl font-bold mb-4">{t("pricing.title")}</h2>
              <p className="text-muted-foreground max-w-2xl mx-auto">
                {t("pricing.description")}
              </p>
              {locale === "en" && (
                <p className="text-sm text-muted-foreground mt-2">
                  {t("pricing.currencyNote")}
                </p>
              )}
            </div>
            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 max-w-6xl mx-auto">
              {plans.map((plan, index) => (
                <Card
                  key={index}
                  className={`relative ${plan.highlight ? "border-primary border-2 shadow-lg" : ""}`}
                >
                  {plan.highlight && (
                    <Badge className="absolute -top-3 left-1/2 -translate-x-1/2">
                      {t("pricing.popular")}
                    </Badge>
                  )}
                  <CardHeader className="text-center pb-2">
                    <CardTitle className="text-xl">{plan.name}</CardTitle>
                    <div className="mt-4">
                      <span className="text-4xl font-bold">{plan.price}</span>
                      {plan.period && (
                        <span className="text-muted-foreground">/{plan.period}</span>
                      )}
                    </div>
                    <CardDescription className="mt-2">{plan.description}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ul className="space-y-3 mb-6">
                      {plan.features.map((feature, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <Check className="h-5 w-5 text-green-500 shrink-0 mt-0.5" />
                          <span className="text-sm">{feature}</span>
                        </li>
                      ))}
                    </ul>
                    <Link href={plan.href} className="block">
                      <Button
                        className="w-full"
                        variant={plan.highlight ? "default" : "outline"}
                      >
                        {plan.cta}
                      </Button>
                    </Link>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </section>

        {/* CTA Section */}
        <section className="py-20">
          <div className="container mx-auto px-4 text-center">
            <h2 className="text-3xl font-bold mb-4">{t("cta.title")}</h2>
            <p className="text-muted-foreground mb-8 max-w-2xl mx-auto">
              {t("cta.description")}
            </p>
            <Link href={`/${locale}/sign-up`}>
              <Button size="lg" className="gap-2">
                {t("cta.button")}
                <ArrowRight className="h-4 w-4" />
              </Button>
            </Link>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t bg-gray-50">
        <div className="container mx-auto px-4 py-12">
          <div className="grid md:grid-cols-4 gap-8">
            <div>
              <h3 className="font-bold text-lg mb-4">SBOMHub</h3>
              <p className="text-sm text-muted-foreground">
                {t("footer.description")}
              </p>
            </div>
            <div>
              <h4 className="font-semibold mb-4">{t("footer.product")}</h4>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li><Link href="#features" className="hover:text-foreground">{t("nav.features")}</Link></li>
                <li><Link href="#pricing" className="hover:text-foreground">{t("nav.pricing")}</Link></li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-4">{t("footer.resources")}</h4>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li><a href="https://github.com/youichi-uda/sbomhub" target="_blank" rel="noopener noreferrer" className="hover:text-foreground">GitHub</a></li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-4">{t("footer.legal")}</h4>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li><Link href="/privacy" className="hover:text-foreground">{t("footer.privacy")}</Link></li>
                <li><Link href="/terms" className="hover:text-foreground">{t("footer.terms")}</Link></li>
                <li><Link href="/legal" className="hover:text-foreground">{t("footer.commercialLaw")}</Link></li>
              </ul>
            </div>
          </div>
          <div className="mt-8 pt-8 border-t text-center text-sm text-muted-foreground">
            <p>&copy; {new Date().getFullYear()} SBOMHub. {t("footer.rights")}</p>
          </div>
        </div>
      </footer>
    </div>
    </>
  );
}
