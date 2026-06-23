import { getTranslations } from "next-intl/server";
import Link from "next/link";
import Script from "next/script";
import {
  AlertTriangle,
  ArrowRight,
  Bell,
  Bot,
  Building2,
  ClipboardCheck,
  FileText,
  Github,
  HelpCircle,
  History,
  KeyRound,
  PenLine,
  Server,
  Share2,
  ShieldCheck,
  Sparkles,
  Terminal,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { WaitlistForm } from "@/components/landing/WaitlistForm";

const BASE_URL = process.env.NEXT_PUBLIC_BASE_URL || "https://sbomhub.app";
const GITHUB_URL = "https://github.com/youichi-uda/sbomhub";

interface Props {
  params: Promise<{ locale: string }>;
}

interface ProblemItem {
  title: string;
  description: string;
}

interface EvidencePackItem {
  title: string;
  description: string;
}

interface RoadmapItem {
  id: string;
  title: string;
  duration: string;
  description: string;
}

const PROBLEM_ICONS = [AlertTriangle, FileText, Bell, ShieldCheck, ClipboardCheck];

const EVIDENCE_PACK_ICONS = [
  PenLine, // VEX drafts
  Bell, // CRA early warning (24h)
  AlertTriangle, // CRA detailed notification (72h)
  FileText, // CRA final report
  ClipboardCheck, // METI prefill
  Sparkles, // SBOM/VEX export
  Share2, // Shareable links
  History, // Audit trail
];

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
            ? "CRA 2026/9 対応 × AI コンプラ成果物レイヤー"
            : "CRA 2026/9 ready AI compliance evidence layer",
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
            ? "SBOM/Syft/Trivy/Dependency-Track の出力から、AI が VEX・CRA 報告書・経産省自己評価の下書きを生成。人間が承認して提出できる成果物に変えるオープンソース基盤。"
            : "Turn SBOMs from Syft/Trivy/Dependency-Track into submittable VEX, CRA reports, and METI self-assessments. AI drafts; humans approve. Open source (AGPL-3.0).",
        url: BASE_URL,
        offers: [
          {
            "@type": "Offer",
            name: "Self-hosted",
            price: "0",
            priceCurrency: "JPY",
            description:
              locale === "ja"
                ? "AGPL-3.0 のセルフホスト版 (全機能, BYOK)"
                : "AGPL-3.0 self-hosted build (all features, BYOK)",
          },
        ],
        featureList: [
          "AI VEX triage (M1)",
          "CRA early warning / detailed notification / final report drafts (M2)",
          "METI self-assessment prefill (M3)",
          "BYOK LLM (OpenAI / Anthropic / Gemini / Ollama)",
          "CycloneDX / SPDX / VEX export",
          "Audit log for AI drafts and human approvals",
        ],
      },
      {
        "@type": "Organization",
        "@id": `${BASE_URL}/#organization`,
        name: "SBOMHub",
        url: BASE_URL,
        logo: `${BASE_URL}/logo.png`,
        sameAs: [GITHUB_URL],
      },
    ],
  };
}

function generateFaqJsonLd(faqItems: { q: string; a: string }[]) {
  return {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: faqItems.map((item) => ({
      "@type": "Question",
      name: item.q,
      acceptedAnswer: {
        "@type": "Answer",
        text: item.a,
      },
    })),
  };
}

export default async function LandingPage({ params }: Props) {
  const { locale } = await params;
  const t = await getTranslations("Landing");
  const faqT = await getTranslations("FAQ");

  const problemItems = t.raw("problem.items") as ProblemItem[];
  const evidencePack = t.raw("solution.evidencePack") as EvidencePackItem[];
  const providers = t.raw("byok.providers") as string[];
  const milestones = t.raw("roadmap.milestones") as RoadmapItem[];

  const faqItems = [
    { q: faqT("q1"), a: faqT("a1") },
    { q: faqT("q2"), a: faqT("a2") },
    { q: faqT("q3"), a: faqT("a3") },
    { q: faqT("q4"), a: faqT("a4") },
    { q: faqT("q5"), a: faqT("a5") },
  ];

  const jsonLd = generateJsonLd(locale);
  const faqJsonLd = generateFaqJsonLd(faqItems);

  return (
    <>
      <Script
        id="json-ld"
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
      <Script
        id="faq-json-ld"
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(faqJsonLd) }}
      />
      <div className="min-h-screen flex flex-col">
        {/* Sunset banner */}
        <div className="bg-amber-50 border-b border-amber-200 text-amber-900 text-sm">
          <div className="container mx-auto px-4 py-2 flex flex-col sm:flex-row sm:items-center sm:justify-center gap-1 text-center">
            <AlertTriangle className="hidden sm:inline-block h-4 w-4 shrink-0" />
            <span>
              {t("sunsetBanner")}{" "}
              <Link
                href={`/${locale}/sunset`}
                className="underline font-medium hover:text-amber-700"
              >
                {t("sunsetBannerLink")}
              </Link>
              .
            </span>
          </div>
        </div>

        {/* Header */}
        <header className="border-b bg-white sticky top-0 z-40">
          <div className="container mx-auto px-4 py-4 flex items-center justify-between">
            <Link href={`/${locale}`} className="text-2xl font-bold text-primary">
              SBOMHub
            </Link>
            <nav className="hidden md:flex items-center gap-6">
              <Link href="#problem" className="text-sm text-muted-foreground hover:text-foreground">
                {t("nav.problem")}
              </Link>
              <Link href="#solution" className="text-sm text-muted-foreground hover:text-foreground">
                {t("nav.solution")}
              </Link>
              <Link href="#byok" className="text-sm text-muted-foreground hover:text-foreground">
                {t("nav.byok")}
              </Link>
              <Link href="#roadmap" className="text-sm text-muted-foreground hover:text-foreground">
                {t("nav.roadmap")}
              </Link>
              <Link href="#faq" className="text-sm text-muted-foreground hover:text-foreground">
                {t("nav.faq")}
              </Link>
            </nav>
            <div className="flex items-center gap-2">
              <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer">
                <Button variant="ghost" size="sm" className="gap-1">
                  <Github className="h-4 w-4" />
                  {t("nav.github")}
                </Button>
              </a>
              <Link href={`/${locale}/sign-in`}>
                <Button variant="ghost" size="sm">
                  {t("nav.signIn")}
                </Button>
              </Link>
              <Link href="#waitlist">
                <Button size="sm">{t("nav.waitlist")}</Button>
              </Link>
            </div>
          </div>
        </header>

        <main className="flex-1">
          {/* Hero */}
          <section className="py-20 bg-gradient-to-b from-blue-50 to-white">
            <div className="container mx-auto px-4 text-center">
              <Badge variant="secondary" className="mb-4">
                {t("hero.badge")}
              </Badge>
              <h1 className="text-4xl md:text-6xl font-bold mb-6 bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent whitespace-pre-line leading-tight">
                {t("hero.title")}
              </h1>
              <p className="text-xl text-muted-foreground mb-8 max-w-3xl mx-auto">
                {t("hero.subtitle")}
              </p>
              <div className="flex flex-col sm:flex-row gap-3 justify-center mb-10">
                <Link href="#waitlist">
                  <Button size="lg" className="gap-2 w-full sm:w-auto">
                    {t("hero.ctaWaitlist")}
                    <ArrowRight className="h-4 w-4" />
                  </Button>
                </Link>
                <Link href="#self-host">
                  <Button size="lg" variant="secondary" className="gap-2 w-full sm:w-auto">
                    <Server className="h-4 w-4" />
                    {t("hero.ctaSelfHost")}
                  </Button>
                </Link>
                <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer">
                  <Button size="lg" variant="outline" className="gap-2 w-full sm:w-auto">
                    <Github className="h-4 w-4" />
                    {t("hero.ctaGithub")}
                  </Button>
                </a>
              </div>
              <div id="waitlist-hero">
                <WaitlistForm variant="hero" />
              </div>
            </div>
          </section>

          {/* Target */}
          <section className="py-12 bg-white border-y">
            <div className="container mx-auto px-4 text-center max-w-3xl">
              <div className="inline-flex items-center gap-2 text-primary mb-3">
                <Building2 className="h-5 w-5" />
                <span className="text-sm font-medium uppercase tracking-wide">
                  {locale === "ja" ? "想定ユーザー" : "Who this is for"}
                </span>
              </div>
              <h2 className="text-2xl font-bold mb-3">{t("target.title")}</h2>
              <p className="text-muted-foreground">{t("target.description")}</p>
            </div>
          </section>

          {/* Problem */}
          <section id="problem" className="py-20 bg-gray-50">
            <div className="container mx-auto px-4">
              <div className="text-center mb-12 max-w-3xl mx-auto">
                <h2 className="text-3xl font-bold mb-4">{t("problem.title")}</h2>
                <p className="text-muted-foreground">{t("problem.description")}</p>
              </div>
              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6 max-w-6xl mx-auto">
                {problemItems.map((item, index) => {
                  const Icon = PROBLEM_ICONS[index] || AlertTriangle;
                  return (
                    <Card key={index} className="border-2 hover:border-amber-300/60 transition-colors">
                      <CardHeader>
                        <Icon className="h-10 w-10 text-amber-600 mb-2" />
                        <CardTitle className="text-lg">{item.title}</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <CardDescription>{item.description}</CardDescription>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            </div>
          </section>

          {/* Solution / Evidence Pack */}
          <section id="solution" className="py-20">
            <div className="container mx-auto px-4">
              <div className="text-center mb-12 max-w-3xl mx-auto">
                <Badge className="mb-3" variant="secondary">
                  {locale === "ja" ? "中核製品" : "Core product"}
                </Badge>
                <h2 className="text-3xl font-bold mb-4">{t("solution.title")}</h2>
                <p className="text-muted-foreground mb-3">{t("solution.description")}</p>
                <p className="text-sm text-primary/80 italic max-w-2xl mx-auto">
                  {t("solution.principle")}
                </p>
              </div>
              <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4 max-w-6xl mx-auto">
                {evidencePack.map((item, index) => {
                  const Icon = EVIDENCE_PACK_ICONS[index] || Sparkles;
                  return (
                    <Card
                      key={index}
                      className="border hover:border-primary/40 hover:shadow-sm transition-all"
                    >
                      <CardHeader className="pb-3">
                        <Icon className="h-8 w-8 text-primary mb-2" />
                        <CardTitle className="text-base">{item.title}</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <CardDescription className="text-sm">
                          {item.description}
                        </CardDescription>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            </div>
          </section>

          {/* BYOK */}
          <section id="byok" className="py-20 bg-gray-50">
            <div className="container mx-auto px-4 max-w-4xl">
              <div className="text-center mb-10">
                <div className="inline-flex items-center gap-2 text-primary mb-3">
                  <KeyRound className="h-5 w-5" />
                  <Bot className="h-5 w-5" />
                </div>
                <h2 className="text-3xl font-bold mb-4">{t("byok.title")}</h2>
                <p className="text-muted-foreground">{t("byok.description")}</p>
              </div>
              <Card className="border-2">
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Sparkles className="h-5 w-5 text-primary" />
                    {t("byok.providersTitle")}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ul className="grid sm:grid-cols-2 gap-3">
                    {providers.map((provider, index) => (
                      <li
                        key={index}
                        className="flex items-center gap-2 rounded-md border px-3 py-2 text-sm bg-white"
                      >
                        <Bot className="h-4 w-4 text-primary shrink-0" />
                        <span>{provider}</span>
                      </li>
                    ))}
                  </ul>
                  <p className="text-xs text-muted-foreground mt-4">
                    {t("byok.selfHostNote")}
                  </p>
                </CardContent>
              </Card>
            </div>
          </section>

          {/* Self-host + CLI side by side */}
          <section id="self-host" className="py-20">
            <div className="container mx-auto px-4 max-w-6xl">
              <div className="grid lg:grid-cols-2 gap-6">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Server className="h-5 w-5 text-primary" />
                      {t("selfHost.title")}
                    </CardTitle>
                    <CardDescription>{t("selfHost.description")}</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <pre className="overflow-x-auto rounded-md bg-gray-900 p-4 text-sm text-gray-100">
                      <code>{t("selfHost.command")}</code>
                    </pre>
                    <p className="text-xs text-muted-foreground">
                      {t("selfHost.dockerHint")}
                    </p>
                    <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer">
                      <Button variant="outline" className="gap-2">
                        <Github className="h-4 w-4" />
                        {t("selfHost.githubCta")}
                      </Button>
                    </a>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Terminal className="h-5 w-5 text-primary" />
                      {t("cli.title")}
                    </CardTitle>
                    <CardDescription>{t("cli.description")}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <pre className="overflow-x-auto rounded-md bg-gray-900 p-4 text-sm text-gray-100">
                      <code>{t("cli.command")}</code>
                    </pre>
                  </CardContent>
                </Card>
              </div>
            </div>
          </section>

          {/* Roadmap */}
          <section id="roadmap" className="py-20 bg-gray-50">
            <div className="container mx-auto px-4">
              <div className="text-center mb-12 max-w-3xl mx-auto">
                <h2 className="text-3xl font-bold mb-4">{t("roadmap.title")}</h2>
                <p className="text-muted-foreground">{t("roadmap.description")}</p>
              </div>
              <div className="grid md:grid-cols-2 lg:grid-cols-5 gap-4 max-w-6xl mx-auto">
                {milestones.map((milestone) => (
                  <Card key={milestone.id} className="border-2">
                    <CardHeader className="pb-3">
                      <Badge variant="secondary" className="w-fit mb-2">
                        {milestone.id} · {milestone.duration}
                      </Badge>
                      <CardTitle className="text-base">{milestone.title}</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <CardDescription className="text-sm leading-relaxed">
                        {milestone.description}
                      </CardDescription>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          </section>

          {/* FAQ */}
          <section id="faq" className="py-20">
            <div className="container mx-auto px-4 max-w-4xl">
              <div className="text-center mb-12">
                <h2 className="text-3xl font-bold mb-4">{faqT("title")}</h2>
              </div>
              <div className="space-y-4">
                {faqItems.map((item, index) => (
                  <details
                    key={index}
                    className="group bg-white rounded-lg border p-6 cursor-pointer hover:border-primary/50 transition-colors"
                  >
                    <summary className="flex items-center justify-between font-medium text-lg list-none">
                      <span className="flex items-center gap-3">
                        <HelpCircle className="h-5 w-5 text-primary shrink-0" />
                        {item.q}
                      </span>
                      <span className="text-muted-foreground group-open:rotate-180 transition-transform ml-4 shrink-0">
                        ▼
                      </span>
                    </summary>
                    <p className="mt-4 text-muted-foreground leading-relaxed pl-8 whitespace-pre-line">
                      {item.a}
                    </p>
                  </details>
                ))}
              </div>
              <div className="mt-10 text-center">
                <p className="text-muted-foreground mb-4">{t("faqCta.description")}</p>
                <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer">
                  <Button variant="outline" className="gap-2">
                    <Github className="h-4 w-4" />
                    {t("faqCta.github")}
                  </Button>
                </a>
              </div>
            </div>
          </section>

          {/* Final waitlist CTA */}
          <section className="py-20 bg-gradient-to-b from-white to-blue-50">
            <div className="container mx-auto px-4 max-w-3xl text-center">
              <h2 className="text-3xl font-bold mb-4">{t("waitlist.title")}</h2>
              <p className="text-muted-foreground mb-8">{t("waitlist.description")}</p>
              <WaitlistForm variant="hero" />
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
                  <li>
                    <Link href="#problem" className="hover:text-foreground">
                      {t("nav.problem")}
                    </Link>
                  </li>
                  <li>
                    <Link href="#solution" className="hover:text-foreground">
                      {t("nav.solution")}
                    </Link>
                  </li>
                  <li>
                    <Link href="#byok" className="hover:text-foreground">
                      {t("nav.byok")}
                    </Link>
                  </li>
                  <li>
                    <Link href="#roadmap" className="hover:text-foreground">
                      {t("nav.roadmap")}
                    </Link>
                  </li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold mb-4">{t("footer.resources")}</h4>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li>
                    <a
                      href={GITHUB_URL}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="hover:text-foreground"
                    >
                      GitHub
                    </a>
                  </li>
                  <li>
                    <Link href={`/${locale}/sunset`} className="hover:text-foreground">
                      {t("footer.sunset")}
                    </Link>
                  </li>
                  <li>
                    <Link href={`/${locale}/sign-in`} className="hover:text-foreground">
                      {t("nav.signIn")}
                    </Link>
                  </li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold mb-4">{t("footer.legal")}</h4>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li>
                    <Link href={`/${locale}/privacy`} className="hover:text-foreground">
                      {t("footer.privacy")}
                    </Link>
                  </li>
                  <li>
                    <Link href={`/${locale}/terms`} className="hover:text-foreground">
                      {t("footer.terms")}
                    </Link>
                  </li>
                  <li>
                    <Link href={`/${locale}/legal`} className="hover:text-foreground">
                      {t("footer.commercialLaw")}
                    </Link>
                  </li>
                </ul>
              </div>
            </div>
            <div className="mt-8 pt-8 border-t text-center text-sm text-muted-foreground">
              <p>
                &copy; {new Date().getFullYear()} SBOMHub. {t("footer.rights")}
              </p>
            </div>
          </div>
        </footer>
      </div>
    </>
  );
}
