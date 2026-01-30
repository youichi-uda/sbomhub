import { getTranslations } from "next-intl/server";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";

interface Props {
  params: Promise<{ locale: string }>;
}

export default async function LegalPage({ params }: Props) {
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
          {isJapanese ? "特定商取引法に基づく表記" : "Commercial Transactions Act Disclosure"}
        </h1>

        <div className="prose prose-gray max-w-none">
          {isJapanese ? (
            <table className="w-full border-collapse">
              <tbody>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50 w-1/3">販売事業者</th>
                  <td className="py-4 px-4">宇田 陽一</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">運営統括責任者</th>
                  <td className="py-4 px-4">宇田 陽一</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">所在地</th>
                  <td className="py-4 px-4">請求があった場合、遅滞なく開示します</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">電話番号</th>
                  <td className="py-4 px-4">請求があった場合、遅滞なく開示します</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">メールアドレス</th>
                  <td className="py-4 px-4">abyo.software@gmail.com</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">販売URL</th>
                  <td className="py-4 px-4">https://sbomhub.app</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">販売価格</th>
                  <td className="py-4 px-4">
                    <ul className="list-disc pl-4 space-y-1">
                      <li>Cloud Starter: 月額2,500円（税込）</li>
                      <li>Cloud Pro: 月額8,000円（税込）</li>
                      <li>Cloud Team: 月額20,000円（税込）</li>
                    </ul>
                  </td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">販売価格以外の必要料金</th>
                  <td className="py-4 px-4">なし</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">支払方法</th>
                  <td className="py-4 px-4">クレジットカード（Visa、Mastercard、American Express、JCB）</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">支払時期</th>
                  <td className="py-4 px-4">サービス利用開始時および毎月の契約更新日</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">サービス提供時期</th>
                  <td className="py-4 px-4">お支払い確認後、即時</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">返品・キャンセル</th>
                  <td className="py-4 px-4">
                    <p>デジタルサービスの性質上、サービス提供開始後の返金はお受けできません。</p>
                    <p className="mt-2">解約は管理画面からいつでも可能です。解約後も契約期間終了までサービスをご利用いただけます。</p>
                  </td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">動作環境</th>
                  <td className="py-4 px-4">
                    <p>最新版のモダンブラウザ（Chrome、Firefox、Safari、Edge）</p>
                    <p className="mt-2">インターネット接続が必要です</p>
                  </td>
                </tr>
              </tbody>
            </table>
          ) : (
            <table className="w-full border-collapse">
              <tbody>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50 w-1/3">Business Operator</th>
                  <td className="py-4 px-4">Yoichi Uda</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">Representative</th>
                  <td className="py-4 px-4">Yoichi Uda</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">Address</th>
                  <td className="py-4 px-4">Disclosed upon request without delay</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">Phone</th>
                  <td className="py-4 px-4">Disclosed upon request without delay</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">Email</th>
                  <td className="py-4 px-4">abyo.software@gmail.com</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">Website</th>
                  <td className="py-4 px-4">https://sbomhub.app</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">Pricing</th>
                  <td className="py-4 px-4">
                    <ul className="list-disc pl-4 space-y-1">
                      <li>Cloud Starter: $17/month (tax included)</li>
                      <li>Cloud Pro: $54/month (tax included)</li>
                      <li>Cloud Team: $134/month (tax included)</li>
                    </ul>
                  </td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">Additional Fees</th>
                  <td className="py-4 px-4">None</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">Payment Methods</th>
                  <td className="py-4 px-4">Credit Card (Visa, Mastercard, American Express, JCB)</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">Payment Timing</th>
                  <td className="py-4 px-4">At service start and on monthly renewal date</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">Service Delivery</th>
                  <td className="py-4 px-4">Immediate upon payment confirmation</td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">Refunds & Cancellation</th>
                  <td className="py-4 px-4">
                    <p>Due to the nature of digital services, refunds are not available after service activation.</p>
                    <p className="mt-2">Cancellation is available anytime from the dashboard. Service remains active until the end of the billing period.</p>
                  </td>
                </tr>
                <tr className="border-b">
                  <th className="py-4 px-4 text-left bg-gray-50">System Requirements</th>
                  <td className="py-4 px-4">
                    <p>Latest version of modern browsers (Chrome, Firefox, Safari, Edge)</p>
                    <p className="mt-2">Internet connection required</p>
                  </td>
                </tr>
              </tbody>
            </table>
          )}
        </div>
      </main>
    </div>
  );
}
