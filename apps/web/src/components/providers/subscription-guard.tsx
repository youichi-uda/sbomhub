"use client";

import { useEffect, useState, ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import { api, SubscriptionResponse } from "@/lib/api";
import { Loader2 } from "lucide-react";

interface SubscriptionGuardProps {
  children: ReactNode;
  locale: string;
}

// Pages that don't require subscription check
const EXEMPT_PATHS = [
  "/billing",
  "/sign-in",
  "/sign-up",
];

export function SubscriptionGuard({ children, locale }: SubscriptionGuardProps) {
  const [loading, setLoading] = useState(true);
  const [checked, setChecked] = useState(false);
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    // Skip check for exempt paths
    const isExempt = EXEMPT_PATHS.some((path) => pathname.includes(path));
    if (isExempt) {
      setLoading(false);
      setChecked(true);
      return;
    }

    checkSubscription();
  }, [pathname]);

  const checkSubscription = async () => {
    try {
      const subscription = await api.billing.getSubscription();

      // Self-hosted mode - no subscription required
      if (subscription.is_self_hosted) {
        setLoading(false);
        setChecked(true);
        return;
      }

      // Billing not enabled - skip check
      if (!subscription.billing_enabled) {
        setLoading(false);
        setChecked(true);
        return;
      }

      // Has subscription or on free plan with usage within limits - allow access
      if (subscription.has_subscription || subscription.plan !== "free") {
        setLoading(false);
        setChecked(true);
        return;
      }

      // Free plan user - redirect to billing on first visit
      // Check if this is a new user (no projects yet)
      const usage = await api.billing.getUsage();

      // If user has no projects, they're likely new - redirect to billing
      if (usage.projects.current === 0) {
        router.replace(`/${locale}/billing`);
        return;
      }

      // Existing free user with projects - allow access
      setLoading(false);
      setChecked(true);
    } catch (error) {
      // On error, allow access (don't block users)
      console.error("Subscription check failed:", error);
      setLoading(false);
      setChecked(true);
    }
  };

  if (loading && !checked) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return <>{children}</>;
}
