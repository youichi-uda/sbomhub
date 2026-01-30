"use client";

import { useEffect, useState } from "react";
import { useTranslations, useLocale } from "next-intl";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Input } from "@/components/ui/input";
import { api, SubscriptionResponse, UsageResponse } from "@/lib/api";
import { Check, ExternalLink, Loader2, CreditCard, Users, FolderOpen, RefreshCw } from "lucide-react";

function usePlans() {
  const t = useTranslations("Billing");
  return [
    {
      id: "free",
      name: t("free"),
      price: "¥0",
      period: "",
      features: [t("projectsLimit", { count: 3 }), t("usersLimit", { count: 1 }), t("basicFeatures")],
    },
    {
      id: "starter",
      name: t("cloudStarter"),
      price: "¥2,500",
      period: t("perMonth"),
      features: [t("projectsLimit", { count: 10 }), t("usersLimit", { count: 3 }), t("emailSupport"), t("autoBackup")],
    },
    {
      id: "pro",
      name: t("cloudPro"),
      price: "¥8,000",
      period: t("perMonth"),
      features: [t("unlimited") + " " + t("projects"), t("usersLimit", { count: 10 }), t("prioritySupport"), t("auditLog")],
    },
    {
      id: "team",
      name: t("cloudTeam"),
      price: "¥20,000",
      period: t("perMonth"),
      features: [t("unlimited") + " " + t("projects"), t("usersLimit", { count: 30 }), t("dedicatedSupport"), t("priorityResponse")],
    },
  ];
}

export default function BillingPage() {
  const t = useTranslations("Billing");
  const tc = useTranslations("Common");
  const locale = useLocale();
  const PLANS = usePlans();
  const [subscription, setSubscription] = useState<SubscriptionResponse | null>(null);
  const [usage, setUsage] = useState<UsageResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [checkoutLoading, setCheckoutLoading] = useState<string | null>(null);
  const [freeLoading, setFreeLoading] = useState(false);
  const [syncLoading, setSyncLoading] = useState(false);
  const [syncMessage, setSyncMessage] = useState<string | null>(null);
  const [showSyncInput, setShowSyncInput] = useState(false);
  const [subscriptionIdInput, setSubscriptionIdInput] = useState("");
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
      setError(t("loadFailed"));
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
      setError(t("checkoutFailed"));
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
      setError(t("portalFailed"));
      console.error(err);
    }
  };

  const handleSelectFree = async () => {
    try {
      setFreeLoading(true);
      await api.billing.selectFreePlan();
      // Reload data to reflect the change
      await loadData();
    } catch (err) {
      setError(t("selectPlanFailed"));
      console.error(err);
    } finally {
      setFreeLoading(false);
    }
  };

  const handleSyncSubscription = async (lsSubId?: string) => {
    try {
      setSyncLoading(true);
      setSyncMessage(null);
      setError(null);
      const result = await api.billing.syncSubscription(lsSubId);
      if (result.status === "synced") {
        setSyncMessage(t("syncSuccess", { plan: result.plan || "" }));
        setShowSyncInput(false);
        setSubscriptionIdInput("");
        await loadData();
      } else if (result.status === "manual_required") {
        setShowSyncInput(true);
        setSyncMessage(result.message || t("manualSyncRequired"));
      } else if (result.status === "no_subscription") {
        setSyncMessage(result.message || t("noSubscriptionFound"));
      }
    } catch (err) {
      setError(t("syncFailed"));
      console.error(err);
    } finally {
      setSyncLoading(false);
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
        <h1 className="text-2xl font-bold mb-6">{t("title")}</h1>
        <Card>
          <CardHeader>
            <CardTitle>{t("selfHostedMode")}</CardTitle>
            <CardDescription>
              {t("selfHostedDescription")}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Badge variant="secondary" className="text-lg px-4 py-2">
              {t("enterpriseUnlimited")}
            </Badge>
          </CardContent>
        </Card>
      </div>
    );
  }

  const currentPlan = subscription?.plan || "";
  const hasSelectedPlan = currentPlan !== "";
  const currentPlanIndex = PLANS.findIndex((p) => p.id === currentPlan);

  return (
    <div className="max-w-6xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">{t("title")}</h1>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-6">
          {error}
        </div>
      )}

      {syncMessage && (
        <div className="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded mb-6">
          {syncMessage}
        </div>
      )}

      {showSyncInput && (
        <Card className="mb-6 border-amber-200 bg-amber-50">
          <CardHeader className="pb-2">
            <CardTitle className="text-lg">{t("manualSyncTitle")}</CardTitle>
            <CardDescription>
              {t("manualSyncDescription")}
              <br />
              <a
                href="https://app.lemonsqueezy.com/subscriptions"
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-600 hover:underline"
              >
                {t("openLemonSqueezy")} →
              </a>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex gap-2">
              <Input
                placeholder={t("subscriptionIdPlaceholder")}
                value={subscriptionIdInput}
                onChange={(e) => setSubscriptionIdInput(e.target.value)}
                className="max-w-xs"
              />
              <Button
                onClick={() => handleSyncSubscription(subscriptionIdInput)}
                disabled={syncLoading || !subscriptionIdInput}
              >
                {syncLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : t("sync")}
              </Button>
              <Button variant="ghost" onClick={() => setShowSyncInput(false)}>
                {tc("cancel")}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Show plan selection prompt for new users */}
      {!hasSelectedPlan && subscription?.billing_enabled && (
        <Card className="mb-8 border-primary border-2 bg-primary/5">
          <CardHeader>
            <CardTitle className="text-xl">{t("selectPlanPrompt")}</CardTitle>
            <CardDescription>
              {t("selectPlanPromptDescription")}
            </CardDescription>
          </CardHeader>
        </Card>
      )}

      {/* Current Plan & Usage */}
      <div className="grid md:grid-cols-2 gap-6 mb-8">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CreditCard className="h-5 w-5" />
              {t("currentPlan")}
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
                    {t("nextRenewal")}: {subscription.subscription.renews_at
                      ? new Date(subscription.subscription.renews_at).toLocaleDateString(locale === 'ja' ? "ja-JP" : "en-US")
                      : subscription.subscription.current_period_end
                        ? new Date(subscription.subscription.current_period_end).toLocaleDateString(locale === 'ja' ? "ja-JP" : "en-US")
                        : "-"}
                  </p>
                )}
              </div>
              <div className="flex gap-2">
                {subscription?.has_subscription && (
                  <Button variant="outline" onClick={handleManageSubscription}>
                    <ExternalLink className="h-4 w-4 mr-2" />
                    {t("manageSubscription")}
                  </Button>
                )}
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => handleSyncSubscription()}
                  disabled={syncLoading}
                  title={t("sync")}
                >
                  <RefreshCw className={`h-4 w-4 ${syncLoading ? "animate-spin" : ""}`} />
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {t("usage")}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {usage && (
              <>
                <div>
                  <div className="flex items-center justify-between text-sm mb-1">
                    <span className="flex items-center gap-2">
                      <FolderOpen className="h-4 w-4" />
                      {t("projects")}
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
                      {t("users")}
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
          <h2 className="text-xl font-semibold mb-4">{t("selectPlan")}</h2>
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
                      {t("currentPlanBadge")}
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
                    {plan.id === "free" ? (
                      <Button
                        className="w-full"
                        variant={isCurrent ? "outline" : "default"}
                        disabled={isCurrent || freeLoading}
                        onClick={handleSelectFree}
                      >
                        {freeLoading ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : isCurrent ? (
                          t("currentPlanBadge")
                        ) : (
                          t("startWithFree")
                        )}
                      </Button>
                    ) : (
                      <Button
                        className="w-full"
                        variant={isCurrent ? "outline" : isUpgrade ? "default" : "secondary"}
                        disabled={isCurrent || checkoutLoading !== null}
                        onClick={() => handleUpgrade(plan.id)}
                      >
                        {checkoutLoading === plan.id ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : isCurrent ? (
                          t("currentPlanBadge")
                        ) : isUpgrade ? (
                          t("upgrade")
                        ) : (
                          t("downgrade")
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
            {t("billingDisabled")}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
