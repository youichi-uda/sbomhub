"use client";

import { useTranslations } from "next-intl";
import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { CheckCircle, AlertTriangle, Clock, HelpCircle, Calendar, Shield } from "lucide-react";
import { EOLStatus } from "@/lib/api";

interface EOLBadgeProps {
  status: EOLStatus;
  eolDate?: string;
  eosDate?: string;
  productLabel?: string;
  cycleVersion?: string;
  lts?: boolean;
  showDetails?: boolean;
  size?: "sm" | "md" | "lg";
}

const statusConfig = {
  active: {
    icon: CheckCircle,
    variant: "default" as const,
    className: "bg-green-600 hover:bg-green-700",
  },
  eol: {
    icon: AlertTriangle,
    variant: "destructive" as const,
    className: "bg-red-600 hover:bg-red-700",
  },
  eos: {
    icon: Clock,
    variant: "secondary" as const,
    className: "bg-orange-500 hover:bg-orange-600 text-white",
  },
  unknown: {
    icon: HelpCircle,
    variant: "outline" as const,
    className: "bg-gray-500 hover:bg-gray-600 text-white",
  },
};

export function EOLBadge({
  status,
  eolDate,
  eosDate,
  productLabel,
  cycleVersion,
  lts,
  showDetails = false,
  size = "md",
}: EOLBadgeProps) {
  const t = useTranslations("EOL");

  const config = statusConfig[status] || statusConfig.unknown;
  const Icon = config.icon;

  const sizeClasses = {
    sm: "h-3 w-3",
    md: "h-3.5 w-3.5",
    lg: "h-4 w-4",
  };

  const eolDateFormatted = eolDate
    ? new Date(eolDate).toLocaleDateString()
    : null;
  const eosDateFormatted = eosDate
    ? new Date(eosDate).toLocaleDateString()
    : null;

  const isEolPast = eolDate ? new Date(eolDate) < new Date() : false;
  const isEosPast = eosDate ? new Date(eosDate) < new Date() : false;

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge
            variant={config.variant}
            className={`gap-1 cursor-help ${config.className}`}
          >
            <Icon className={sizeClasses[size]} />
            {t(status)}
            {lts && <Shield className={`${sizeClasses[size]} ml-0.5`} />}
          </Badge>
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-xs">
          <div className="space-y-1.5">
            <p className="font-semibold">{t(`description.${status}Title`)}</p>
            <p className="text-sm text-muted-foreground">
              {t(`description.${status}`)}
            </p>
            {productLabel && (
              <div className="text-sm">
                <span className="text-muted-foreground">{t("product")}: </span>
                <span className="font-medium">{productLabel}</span>
                {cycleVersion && (
                  <span className="text-muted-foreground"> ({cycleVersion})</span>
                )}
              </div>
            )}
            {lts && (
              <div className="flex items-center gap-1 text-sm text-blue-400">
                <Shield className="h-3 w-3" />
                {t("lts")}
              </div>
            )}
            {eolDateFormatted && (
              <div className="flex items-center gap-1 text-sm">
                <Calendar className="h-3 w-3" />
                <span className={isEolPast ? "text-red-400" : ""}>
                  {t("eolDate")}: {eolDateFormatted}
                  {isEolPast && ` (${t("past")})`}
                </span>
              </div>
            )}
            {eosDateFormatted && eosDate !== eolDate && (
              <div className="flex items-center gap-1 text-sm">
                <Clock className="h-3 w-3" />
                <span className={isEosPast ? "text-orange-400" : ""}>
                  {t("eosDate")}: {eosDateFormatted}
                  {isEosPast && ` (${t("past")})`}
                </span>
              </div>
            )}
          </div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

// Compact version for lists
export function EOLIndicator({
  status,
  lts,
}: {
  status?: EOLStatus;
  lts?: boolean;
}) {
  const t = useTranslations("EOL");

  if (!status || status === "unknown") {
    return null;
  }

  const config = statusConfig[status];
  const Icon = config.icon;

  const colorClasses = {
    active: "text-green-500",
    eol: "text-red-500",
    eos: "text-orange-500",
    unknown: "text-gray-500",
  };

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className={`inline-flex items-center ${colorClasses[status]}`}>
            <Icon className="h-4 w-4" />
            {lts && <Shield className="h-3 w-3 ml-0.5 text-blue-500" />}
          </span>
        </TooltipTrigger>
        <TooltipContent>
          <p>{t(`description.${status}`)}</p>
          {lts && <p className="text-blue-400">{t("lts")}</p>}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

// Summary card component
export function EOLSummaryCard({
  active,
  eol,
  eos,
  unknown,
  total,
}: {
  active: number;
  eol: number;
  eos: number;
  unknown: number;
  total: number;
}) {
  const t = useTranslations("EOL");

  return (
    <div className="grid grid-cols-4 gap-4 text-center">
      <div className="space-y-1">
        <div className="flex items-center justify-center gap-1 text-green-500">
          <CheckCircle className="h-4 w-4" />
          <span className="text-2xl font-bold">{active}</span>
        </div>
        <p className="text-xs text-muted-foreground">{t("active")}</p>
      </div>
      <div className="space-y-1">
        <div className="flex items-center justify-center gap-1 text-orange-500">
          <Clock className="h-4 w-4" />
          <span className="text-2xl font-bold">{eos}</span>
        </div>
        <p className="text-xs text-muted-foreground">{t("eos")}</p>
      </div>
      <div className="space-y-1">
        <div className="flex items-center justify-center gap-1 text-red-500">
          <AlertTriangle className="h-4 w-4" />
          <span className="text-2xl font-bold">{eol}</span>
        </div>
        <p className="text-xs text-muted-foreground">{t("eol")}</p>
      </div>
      <div className="space-y-1">
        <div className="flex items-center justify-center gap-1 text-gray-500">
          <HelpCircle className="h-4 w-4" />
          <span className="text-2xl font-bold">{unknown}</span>
        </div>
        <p className="text-xs text-muted-foreground">{t("unknown")}</p>
      </div>
    </div>
  );
}
