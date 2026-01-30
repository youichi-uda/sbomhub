"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { api, SubscriptionResponse, UsageResponse } from "@/lib/api";
import { Check, ExternalLink, Loader2, CreditCard, Users, FolderOpen } from "lucide-react";

const PLANS = [
  {
    id: "free",
    name: "Free",
    price: "¥0",
    period: "",
    features: ["3 プロジェクト", "1 ユーザー", "基本機能"],
  },
  {
    id: "starter",
    name: "Cloud Starter",
    price: "¥2,500",
    period: "月",
    features: ["10 プロジェクト", "3 ユーザー", "メールサポート", "自動バックアップ"],
  },
  {
    id: "pro",
    name: "Cloud Pro",
    price: "¥8,000",
    period: "月",
    features: ["無制限プロジェクト", "10 ユーザー", "優先サポート", "SLA 99.9%", "監査ログ"],
  },
  {
    id: "team",
    name: "Cloud Team",
    price: "¥20,000",
    period: "月",
    features: ["無制限プロジェクト", "30 ユーザー", "専任サポート", "SLA 99.9%", "優先対応"],
  },
];

export default function BillingPage() {
  const [subscription, setSubscription] = useState<SubscriptionResponse | null>(null);
  const [usage, setUsage] = useState<UsageResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [checkoutLoading, setCheckoutLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [subData, usageData] = await Promise.all([
        api.billing.getSubscription(),
        api.billing.getUsage(),
      ]);
      setSubscription(subData);
      setUsage(usageData);
    } catch (err) {
      setError("データの読み込みに失敗しました");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleUpgrade = async (plan: string) => {
    try {
      setCheckoutLoading(plan);
      const { url } = await api.billing.createCheckout(plan);
      window.location.href = url;
    } catch (err) {
      setError("チェックアウトの作成に失敗しました");
      console.error(err);
    } finally {
      setCheckoutLoading(null);
    }
  };

  const handleManageSubscription = async () => {
    try {
      const { url } = await api.billing.getPortalUrl();
      window.open(url, "_blank");
    } catch (err) {
      setError("ポータルURLの取得に失敗しました");
      console.error(err);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (subscription?.is_self_hosted) {
    return (
      <div className="p-6 max-w-4xl mx-auto">
        <h1 className="text-2xl font-bold mb-6">プラン・お支払い</h1>
        <Card>
          <CardHeader>
            <CardTitle>Self-Hosted モード</CardTitle>
            <CardDescription>
              セルフホスト版では全機能が無制限でご利用いただけます。
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Badge variant="secondary" className="text-lg px-4 py-2">
              Enterprise (無制限)
            </Badge>
          </CardContent>
        </Card>
      </div>
    );
  }

  const currentPlan = subscription?.plan || "free";
  const currentPlanIndex = PLANS.findIndex((p) => p.id === currentPlan);

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">プラン・お支払い</h1>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-6">
          {error}
        </div>
      )}

      {/* Current Plan & Usage */}
      <div className="grid md:grid-cols-2 gap-6 mb-8">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CreditCard className="h-5 w-5" />
              現在のプラン
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-2xl font-bold">
                  {PLANS.find((p) => p.id === currentPlan)?.name || currentPlan}
                </p>
                {subscription?.has_subscription && subscription.subscription && (
                  <p className="text-sm text-muted-foreground mt-1">
                    次回更新: {new Date(subscription.subscription.current_period_end).toLocaleDateString("ja-JP")}
                  </p>
                )}
              </div>
              {subscription?.has_subscription && (
                <Button variant="outline" onClick={handleManageSubscription}>
                  <ExternalLink className="h-4 w-4 mr-2" />
                  サブスクリプション管理
                </Button>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              使用状況
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {usage && (
              <>
                <div>
                  <div className="flex items-center justify-between text-sm mb-1">
                    <span className="flex items-center gap-2">
                      <FolderOpen className="h-4 w-4" />
                      プロジェクト
                    </span>
                    <span>
                      {usage.projects.current} / {usage.projects.limit === -1 ? "∞" : usage.projects.limit}
                    </span>
                  </div>
                  {usage.projects.limit !== -1 && (
                    <Progress
                      value={(usage.projects.current / usage.projects.limit) * 100}
                      className="h-2"
                    />
                  )}
                </div>
                <div>
                  <div className="flex items-center justify-between text-sm mb-1">
                    <span className="flex items-center gap-2">
                      <Users className="h-4 w-4" />
                      ユーザー
                    </span>
                    <span>
                      {usage.users.current} / {usage.users.limit === -1 ? "∞" : usage.users.limit}
                    </span>
                  </div>
                  {usage.users.limit !== -1 && (
                    <Progress
                      value={(usage.users.current / usage.users.limit) * 100}
                      className="h-2"
                    />
                  )}
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Plan Selection */}
      {subscription?.billing_enabled && (
        <>
          <h2 className="text-xl font-semibold mb-4">プランを選択</h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
            {PLANS.map((plan, index) => {
              const isCurrent = plan.id === currentPlan;
              const isDowngrade = index < currentPlanIndex;
              const isUpgrade = index > currentPlanIndex;

              return (
                <Card
                  key={plan.id}
                  className={`relative ${isCurrent ? "border-primary border-2" : ""}`}
                >
                  {isCurrent && (
                    <Badge className="absolute -top-3 left-1/2 -translate-x-1/2">
                      現在のプラン
                    </Badge>
                  )}
                  <CardHeader className="pb-2">
                    <CardTitle className="text-lg">{plan.name}</CardTitle>
                    <div className="mt-2">
                      <span className="text-2xl font-bold">{plan.price}</span>
                      {plan.period && (
                        <span className="text-muted-foreground">/{plan.period}</span>
                      )}
                    </div>
                  </CardHeader>
                  <CardContent>
                    <ul className="space-y-2 mb-4">
                      {plan.features.map((feature, i) => (
                        <li key={i} className="flex items-start gap-2 text-sm">
                          <Check className="h-4 w-4 text-green-500 shrink-0 mt-0.5" />
                          {feature}
                        </li>
                      ))}
                    </ul>
                    {plan.id !== "free" && (
                      <Button
                        className="w-full"
                        variant={isCurrent ? "outline" : isUpgrade ? "default" : "secondary"}
                        disabled={isCurrent || checkoutLoading !== null}
                        onClick={() => handleUpgrade(plan.id)}
                      >
                        {checkoutLoading === plan.id ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : isCurrent ? (
                          "現在のプラン"
                        ) : isUpgrade ? (
                          "アップグレード"
                        ) : (
                          "ダウングレード"
                        )}
                      </Button>
                    )}
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </>
      )}

      {!subscription?.billing_enabled && (
        <Card>
          <CardContent className="py-8 text-center text-muted-foreground">
            課金機能は現在無効になっています。
          </CardContent>
        </Card>
      )}
    </div>
  );
}
