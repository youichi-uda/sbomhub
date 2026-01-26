import { getTranslations } from "next-intl/server";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";

interface Props {
  params: Promise<{ locale: string }>;
}

export default async function TermsPage({ params }: Props) {
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
          {isJapanese ? "利用規約" : "Terms of Service"}
        </h1>

        <div className="prose prose-gray max-w-none">
          {isJapanese ? (
            <>
              <p className="text-muted-foreground mb-6">最終更新日: 2025年1月26日</p>

              <h2 className="text-xl font-semibold mt-8 mb-4">1. サービスの概要</h2>
              <p>SBOMHub（以下「当サービス」）は、ソフトウェア部品表（SBOM）の管理、脆弱性の可視化、コンプライアンスチェックを提供するクラウドサービスです。</p>

              <h2 className="text-xl font-semibold mt-8 mb-4">2. 利用資格</h2>
              <p>当サービスを利用するには、以下の条件を満たす必要があります：</p>
              <ul className="list-disc pl-6 my-4 space-y-2">
                <li>法人または個人事業主であること</li>
                <li>本規約に同意すること</li>
                <li>正確なアカウント情報を提供すること</li>
              </ul>

              <h2 className="text-xl font-semibold mt-8 mb-4">3. 料金と支払い</h2>
              <ul className="list-disc pl-6 my-4 space-y-2">
                <li>料金プランは当サービスのウェブサイトに記載されています</li>
                <li>支払いはクレジットカードによる月額課金となります</li>
                <li>料金は変更される場合があり、変更の30日前に通知します</li>
                <li>解約は月末まで有効で、日割り返金は行いません</li>
              </ul>

              <h2 className="text-xl font-semibold mt-8 mb-4">4. データの取り扱い</h2>
              <ul className="list-disc pl-6 my-4 space-y-2">
                <li>お客様がアップロードしたSBOMデータの所有権はお客様に帰属します</li>
                <li>当サービスは、サービス提供に必要な範囲でのみデータを処理します</li>
                <li>アカウント削除時、お客様のデータは30日以内に削除されます</li>
              </ul>

              <h2 className="text-xl font-semibold mt-8 mb-4">5. 禁止事項</h2>
              <p>以下の行為は禁止されています：</p>
              <ul className="list-disc pl-6 my-4 space-y-2">
                <li>不正アクセスやセキュリティ機能の回避</li>
                <li>サービスの逆コンパイルやリバースエンジニアリング</li>
                <li>他のユーザーへの妨害行為</li>
                <li>違法な目的での使用</li>
              </ul>

              <h2 className="text-xl font-semibold mt-8 mb-4">6. 免責事項</h2>
              <p>当サービスは「現状有姿」で提供され、特定目的への適合性や商品性について保証しません。脆弱性情報は参考情報であり、完全性を保証するものではありません。</p>

              <h2 className="text-xl font-semibold mt-8 mb-4">7. 責任の制限</h2>
              <p>当サービスの利用に起因する損害について、当社の責任は、お客様が過去12ヶ月間に支払った利用料金を上限とします。</p>

              <h2 className="text-xl font-semibold mt-8 mb-4">8. 準拠法と管轄</h2>
              <p>本規約は日本法に準拠し、紛争が生じた場合は東京地方裁判所を第一審の専属的合意管轄裁判所とします。</p>

              <h2 className="text-xl font-semibold mt-8 mb-4">9. お問い合わせ</h2>
              <p>本規約に関するお問い合わせは、以下までご連絡ください：</p>
              <p className="mt-2">メール: abyo.software@gmail.com</p>
            </>
          ) : (
            <>
              <p className="text-muted-foreground mb-6">Last updated: January 26, 2025</p>

              <h2 className="text-xl font-semibold mt-8 mb-4">1. Service Overview</h2>
              <p>SBOMHub ("the Service") is a cloud service that provides Software Bill of Materials (SBOM) management, vulnerability visualization, and compliance checking.</p>

              <h2 className="text-xl font-semibold mt-8 mb-4">2. Eligibility</h2>
              <p>To use the Service, you must:</p>
              <ul className="list-disc pl-6 my-4 space-y-2">
                <li>Be a business entity or individual contractor</li>
                <li>Agree to these terms</li>
                <li>Provide accurate account information</li>
              </ul>

              <h2 className="text-xl font-semibold mt-8 mb-4">3. Pricing and Payment</h2>
              <ul className="list-disc pl-6 my-4 space-y-2">
                <li>Pricing plans are listed on our website</li>
                <li>Payment is by credit card on a monthly subscription basis</li>
                <li>Prices may change with 30 days notice</li>
                <li>Cancellation is effective at month end; no prorated refunds</li>
              </ul>

              <h2 className="text-xl font-semibold mt-8 mb-4">4. Data Handling</h2>
              <ul className="list-disc pl-6 my-4 space-y-2">
                <li>You retain ownership of SBOM data you upload</li>
                <li>We process data only as necessary to provide the Service</li>
                <li>Upon account deletion, your data will be deleted within 30 days</li>
              </ul>

              <h2 className="text-xl font-semibold mt-8 mb-4">5. Prohibited Activities</h2>
              <p>The following activities are prohibited:</p>
              <ul className="list-disc pl-6 my-4 space-y-2">
                <li>Unauthorized access or circumventing security features</li>
                <li>Decompiling or reverse engineering the Service</li>
                <li>Interfering with other users</li>
                <li>Using the Service for illegal purposes</li>
              </ul>

              <h2 className="text-xl font-semibold mt-8 mb-4">6. Disclaimer</h2>
              <p>The Service is provided "as is" without warranties of merchantability or fitness for a particular purpose. Vulnerability information is for reference only and is not guaranteed to be complete.</p>

              <h2 className="text-xl font-semibold mt-8 mb-4">7. Limitation of Liability</h2>
              <p>Our liability for damages arising from use of the Service is limited to the fees you paid in the preceding 12 months.</p>

              <h2 className="text-xl font-semibold mt-8 mb-4">8. Governing Law</h2>
              <p>These terms are governed by the laws of Japan. Any disputes shall be subject to the exclusive jurisdiction of the Tokyo District Court.</p>

              <h2 className="text-xl font-semibold mt-8 mb-4">9. Contact Us</h2>
              <p>For questions about these terms, please contact us at:</p>
              <p className="mt-2">Email: abyo.software@gmail.com</p>
            </>
          )}
        </div>
      </main>
    </div>
  );
}
