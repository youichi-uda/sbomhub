import { getTranslations } from "next-intl/server";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { ArrowLeft } from "lucide-react";

interface Props {
  params: Promise<{ locale: string }>;
}

export default async function PrivacyPage({ params }: Props) {
  const { locale } = await params;
  const isJapanese = locale === "ja";

  return (
    <div className="min-h-screen bg-white">
      <header className="border-b">
        <div className="container mx-auto px-4 py-4">
          <Link href={`/${locale}`} className="inline-flex items-center gap-2 text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-4 w-4" />
            {isJapanese ? "トップに戻る" : "Back to Home"}
          </Link>
        </div>
      </header>

      <main className="container mx-auto px-4 py-12 max-w-3xl">
        <h1 className="text-3xl font-bold mb-8">
          {isJapanese ? "プライバシーポリシー" : "Privacy Policy"}
        </h1>

        <div className="prose prose-gray max-w-none">
          {isJapanese ? (
            <>
              <p className="text-muted-foreground mb-6">最終更新日: 2025年1月26日</p>

              <h2 className="text-xl font-semibold mt-8 mb-4">1. はじめに</h2>
              <p>SBOMHub（以下「当サービス」）は、お客様のプライバシーを尊重し、個人情報の保護に努めています。本プライバシーポリシーは、当サービスがどのような情報を収集し、どのように使用するかを説明します。</p>

              <h2 className="text-xl font-semibold mt-8 mb-4">2. 収集する情報</h2>
              <p>当サービスは以下の情報を収集する場合があります：</p>
              <ul className="list-disc pl-6 my-4 space-y-2">
                <li>アカウント情報（メールアドレス、氏名、組織名）</li>
                <li>利用状況データ（アクセスログ、機能の使用状況）</li>
                <li>お客様がアップロードしたSBOMデータ</li>
                <li>お支払い情報（決済代行サービスを通じて処理）</li>
              </ul>

              <h2 className="text-xl font-semibold mt-8 mb-4">3. 情報の利用目的</h2>
              <p>収集した情報は以下の目的で使用します：</p>
              <ul className="list-disc pl-6 my-4 space-y-2">
                <li>サービスの提供および改善</li>
                <li>カスタマーサポートの提供</li>
                <li>サービスに関する重要なお知らせの送信</li>
                <li>利用規約の遵守の確認</li>
              </ul>

              <h2 className="text-xl font-semibold mt-8 mb-4">4. 情報の共有</h2>
              <p>当サービスは、以下の場合を除き、お客様の個人情報を第三者と共有しません：</p>
              <ul className="list-disc pl-6 my-4 space-y-2">
                <li>お客様の同意がある場合</li>
                <li>法的要請に応じる必要がある場合</li>
                <li>サービス提供に必要な業務委託先との共有（決済処理等）</li>
              </ul>

              <h2 className="text-xl font-semibold mt-8 mb-4">5. データの保護</h2>
              <p>当サービスは、お客様のデータを保護するために適切な技術的・組織的措置を講じています。これには、SSL/TLS暗号化、アクセス制御、定期的なセキュリティ監査が含まれます。</p>

              <h2 className="text-xl font-semibold mt-8 mb-4">6. お問い合わせ</h2>
              <p>プライバシーに関するご質問やご要望は、以下までご連絡ください：</p>
              <p className="mt-2">メール: abyo.software@gmail.com</p>
            </>
          ) : (
            <>
              <p className="text-muted-foreground mb-6">Last updated: January 26, 2025</p>

              <h2 className="text-xl font-semibold mt-8 mb-4">1. Introduction</h2>
              <p>SBOMHub ("the Service") respects your privacy and is committed to protecting your personal information. This Privacy Policy explains what information we collect and how we use it.</p>

              <h2 className="text-xl font-semibold mt-8 mb-4">2. Information We Collect</h2>
              <p>We may collect the following information:</p>
              <ul className="list-disc pl-6 my-4 space-y-2">
                <li>Account information (email address, name, organization)</li>
                <li>Usage data (access logs, feature usage)</li>
                <li>SBOM data you upload</li>
                <li>Payment information (processed through payment providers)</li>
              </ul>

              <h2 className="text-xl font-semibold mt-8 mb-4">3. How We Use Information</h2>
              <p>We use collected information for:</p>
              <ul className="list-disc pl-6 my-4 space-y-2">
                <li>Providing and improving the Service</li>
                <li>Customer support</li>
                <li>Sending important service notifications</li>
                <li>Ensuring compliance with terms of service</li>
              </ul>

              <h2 className="text-xl font-semibold mt-8 mb-4">4. Information Sharing</h2>
              <p>We do not share your personal information with third parties except:</p>
              <ul className="list-disc pl-6 my-4 space-y-2">
                <li>With your consent</li>
                <li>To comply with legal requirements</li>
                <li>With service providers necessary for operations (payment processing, etc.)</li>
              </ul>

              <h2 className="text-xl font-semibold mt-8 mb-4">5. Data Protection</h2>
              <p>We implement appropriate technical and organizational measures to protect your data, including SSL/TLS encryption, access controls, and regular security audits.</p>

              <h2 className="text-xl font-semibold mt-8 mb-4">6. Contact Us</h2>
              <p>For privacy-related questions or requests, please contact us at:</p>
              <p className="mt-2">Email: abyo.software@gmail.com</p>
            </>
          )}
        </div>
      </main>
    </div>
  );
}
