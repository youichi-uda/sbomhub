'use client';

import { useState, useEffect, useCallback } from 'react';
import { useTranslations } from 'next-intl';
import { Loader2, Clock, Target, TrendingUp, ShieldCheck, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { api, AnalyticsSummary, MTTRResult, SLOAchievement } from '@/lib/api';

export default function AnalyticsPage() {
    const t = useTranslations("Analytics");
    const tc = useTranslations("Common");
    const tv = useTranslations("Vulnerabilities");
    const [summary, setSummary] = useState<AnalyticsSummary | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [days, setDays] = useState(30);

    const loadData = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await api.analytics.getSummary(days);
            setSummary(data);
        } catch (err) {
            setError(tc("error"));
            console.error(err);
        } finally {
            setLoading(false);
        }
    }, [days]);

    useEffect(() => {
        loadData();
    }, [loadData]);

    const formatHours = (hours: number) => {
        if (hours < 24) return `${hours.toFixed(1)} ${t("hours")}`;
        const d = Math.floor(hours / 24);
        const h = hours % 24;
        return `${d} ${d === 1 ? t("day") : t("days")}${h > 0 ? ` ${h.toFixed(0)} ${t("hours")}` : ''}`;
    };

    const getSeverityColor = (severity: string) => {
        switch (severity.toUpperCase()) {
            case 'CRITICAL': return 'text-red-500';
            case 'HIGH': return 'text-orange-500';
            case 'MEDIUM': return 'text-yellow-500';
            case 'LOW': return 'text-green-500';
            default: return 'text-gray-500';
        }
    };

    const getSeverityBgColor = (severity: string) => {
        switch (severity.toUpperCase()) {
            case 'CRITICAL': return 'bg-red-100 dark:bg-red-900/30';
            case 'HIGH': return 'bg-orange-100 dark:bg-orange-900/30';
            case 'MEDIUM': return 'bg-yellow-100 dark:bg-yellow-900/30';
            case 'LOW': return 'bg-green-100 dark:bg-green-900/30';
            default: return 'bg-gray-100 dark:bg-gray-900/30';
        }
    };

    if (loading && !summary) {
        return (
            <div className="flex items-center justify-center h-64">
                <Loader2 className="w-8 h-8 animate-spin text-primary" />
            </div>
        );
    }

    return (
        <div className="py-8 px-4">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h1 className="text-2xl font-bold">{t("title")}</h1>
                    <p className="text-sm text-muted-foreground mt-1">
                        {t("description")}
                    </p>
                </div>
                <div className="flex items-center gap-2">
                    <label className="text-sm text-muted-foreground">{t("period")}:</label>
                    <select
                        value={days}
                        onChange={(e) => setDays(parseInt(e.target.value))}
                        className="bg-background border border-border rounded-lg px-3 py-2"
                    >
                        <option value={7}>{t("days7")}</option>
                        <option value={30}>{t("days30")}</option>
                        <option value={90}>{t("days90")}</option>
                        <option value={180}>{t("days180")}</option>
                        <option value={365}>{t("year1")}</option>
                    </select>
                </div>
            </div>

            {error && (
                <div className="mb-6 p-4 bg-destructive/10 border border-destructive/20 rounded-lg text-destructive">
                    {error}
                </div>
            )}

            {/* Quick Stats */}
            {summary && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
                    <div className="bg-card border border-border rounded-lg p-4">
                        <div className="flex items-center gap-3">
                            <div className="p-2 bg-red-100 dark:bg-red-900/30 rounded-lg">
                                <AlertTriangle className="w-5 h-5 text-red-500" />
                            </div>
                            <div>
                                <p className="text-sm text-muted-foreground">{t("openVulnerabilities")}</p>
                                <p className="text-2xl font-bold">{summary.summary.total_open_vulnerabilities}</p>
                            </div>
                        </div>
                    </div>

                    <div className="bg-card border border-border rounded-lg p-4">
                        <div className="flex items-center gap-3">
                            <div className="p-2 bg-green-100 dark:bg-green-900/30 rounded-lg">
                                <CheckCircle2 className="w-5 h-5 text-green-500" />
                            </div>
                            <div>
                                <p className="text-sm text-muted-foreground">{t("resolvedRecently", { days: 30 })}</p>
                                <p className="text-2xl font-bold">{summary.summary.resolved_last_30_days}</p>
                            </div>
                        </div>
                    </div>

                    <div className="bg-card border border-border rounded-lg p-4">
                        <div className="flex items-center gap-3">
                            <div className="p-2 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
                                <Clock className="w-5 h-5 text-blue-500" />
                            </div>
                            <div>
                                <p className="text-sm text-muted-foreground">{t("averageMttr")}</p>
                                <p className="text-2xl font-bold">{formatHours(summary.summary.average_mttr_hours)}</p>
                            </div>
                        </div>
                    </div>

                    <div className="bg-card border border-border rounded-lg p-4">
                        <div className="flex items-center gap-3">
                            <div className="p-2 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
                                <Target className="w-5 h-5 text-purple-500" />
                            </div>
                            <div>
                                <p className="text-sm text-muted-foreground">{t("sloAchievementRate")}</p>
                                <p className="text-2xl font-bold">{summary.summary.overall_slo_achievement_pct.toFixed(1)}%</p>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* MTTR by Severity */}
                {summary && (
                    <div className="bg-card border border-border rounded-lg p-6">
                        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
                            <Clock className="w-5 h-5" />
                            {t("mttrTitle")}
                        </h2>
                        <div className="space-y-4">
                            {summary.mttr.map((m: MTTRResult) => (
                                <div key={m.severity} className="flex items-center gap-4">
                                    <div className={`w-20 px-2 py-1 rounded text-center text-sm font-medium ${getSeverityBgColor(m.severity)} ${getSeverityColor(m.severity)}`}>
                                        {m.severity}
                                    </div>
                                    <div className="flex-1">
                                        <div className="flex items-center justify-between mb-1">
                                            <span className="text-sm">
                                                {formatHours(m.mttr_hours)}
                                                <span className="text-muted-foreground ml-1">
                                                    ({m.count} {t("cases")})
                                                </span>
                                            </span>
                                            <span className="text-sm text-muted-foreground">
                                                {t("target")}: {formatHours(m.target_hours)}
                                            </span>
                                        </div>
                                        <div className="h-2 bg-muted rounded-full overflow-hidden">
                                            <div
                                                className={`h-full rounded-full transition-all ${m.on_target ? 'bg-green-500' : 'bg-red-500'}`}
                                                style={{
                                                    width: `${Math.min(100, (m.mttr_hours / m.target_hours) * 100)}%`
                                                }}
                                            />
                                        </div>
                                    </div>
                                    {m.on_target ? (
                                        <CheckCircle2 className="w-5 h-5 text-green-500" />
                                    ) : (
                                        <AlertTriangle className="w-5 h-5 text-red-500" />
                                    )}
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* SLO Achievement */}
                {summary && (
                    <div className="bg-card border border-border rounded-lg p-6">
                        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
                            <Target className="w-5 h-5" />
                            {t("sloTitle")}
                        </h2>
                        <div className="space-y-4">
                            {summary.slo_achievement.map((slo: SLOAchievement) => (
                                <div key={slo.severity} className="flex items-center gap-4">
                                    <div className={`w-20 px-2 py-1 rounded text-center text-sm font-medium ${getSeverityBgColor(slo.severity)} ${getSeverityColor(slo.severity)}`}>
                                        {slo.severity}
                                    </div>
                                    <div className="flex-1">
                                        <div className="flex items-center justify-between mb-1">
                                            <span className="text-sm font-medium">
                                                {slo.achievement_pct.toFixed(1)}%
                                            </span>
                                            <span className="text-sm text-muted-foreground">
                                                {slo.on_target_count}/{slo.total_count} {t("cases")}
                                            </span>
                                        </div>
                                        <div className="h-2 bg-muted rounded-full overflow-hidden">
                                            <div
                                                className={`h-full rounded-full transition-all ${slo.achievement_pct >= 80 ? 'bg-green-500' : slo.achievement_pct >= 50 ? 'bg-yellow-500' : 'bg-red-500'}`}
                                                style={{ width: `${slo.achievement_pct}%` }}
                                            />
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                        <div className="mt-4 pt-4 border-t border-border">
                            <p className="text-sm text-muted-foreground">
                                {t("sloDescription")}
                            </p>
                        </div>
                    </div>
                )}
            </div>

            {/* Vulnerability Trend */}
            {summary && summary.vulnerability_trend.length > 0 && (
                <div className="mt-6 bg-card border border-border rounded-lg p-6">
                    <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
                        <TrendingUp className="w-5 h-5" />
                        {t("vulnerabilityTrend")}
                    </h2>
                    <div className="overflow-x-auto">
                        <div className="min-w-[600px]">
                            {/* Simple bar chart representation */}
                            <div className="flex items-end gap-1 h-48">
                                {summary.vulnerability_trend.slice(-30).map((point, index) => {
                                    const maxTotal = Math.max(...summary.vulnerability_trend.map(p => p.total), 1);
                                    const height = (point.total / maxTotal) * 100;
                                    return (
                                        <div
                                            key={index}
                                            className="flex-1 flex flex-col items-center"
                                            title={`${point.date}: Critical=${point.critical}, High=${point.high}, Medium=${point.medium}, Low=${point.low}`}
                                        >
                                            <div
                                                className="w-full bg-gradient-to-t from-red-500 via-orange-400 to-yellow-300 rounded-t"
                                                style={{ height: `${height}%` }}
                                            />
                                        </div>
                                    );
                                })}
                            </div>
                            <div className="flex justify-between mt-2 text-xs text-muted-foreground">
                                <span>{summary.vulnerability_trend[0]?.date}</span>
                                <span>{summary.vulnerability_trend[summary.vulnerability_trend.length - 1]?.date}</span>
                            </div>
                        </div>
                    </div>
                    <div className="mt-4 flex items-center gap-6 text-sm">
                        <div className="flex items-center gap-2">
                            <div className="w-3 h-3 rounded bg-red-500" />
                            <span>Critical</span>
                        </div>
                        <div className="flex items-center gap-2">
                            <div className="w-3 h-3 rounded bg-orange-500" />
                            <span>High</span>
                        </div>
                        <div className="flex items-center gap-2">
                            <div className="w-3 h-3 rounded bg-yellow-500" />
                            <span>Medium</span>
                        </div>
                        <div className="flex items-center gap-2">
                            <div className="w-3 h-3 rounded bg-green-500" />
                            <span>Low</span>
                        </div>
                    </div>
                </div>
            )}

            {/* Compliance Trend */}
            {summary && summary.compliance_trend && summary.compliance_trend.length > 0 && (
                <div className="mt-6 bg-card border border-border rounded-lg p-6">
                    <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
                        <ShieldCheck className="w-5 h-5" />
                        {t("complianceScoreTrend")}
                    </h2>
                    <div className="flex items-center gap-4 mb-4">
                        <div className="text-3xl font-bold">
                            {summary.summary.current_compliance_score}/{summary.summary.compliance_max_score}
                        </div>
                        <div className="text-muted-foreground">
                            ({((summary.summary.current_compliance_score / summary.summary.compliance_max_score) * 100).toFixed(1)}%)
                        </div>
                    </div>
                    <div className="space-y-2">
                        {summary.compliance_trend.slice(-7).map((point, index) => (
                            <div key={index} className="flex items-center gap-4">
                                <span className="w-24 text-sm text-muted-foreground">{point.date}</span>
                                <div className="flex-1 h-4 bg-muted rounded-full overflow-hidden">
                                    <div
                                        className="h-full bg-primary rounded-full"
                                        style={{ width: `${point.percentage}%` }}
                                    />
                                </div>
                                <span className="w-12 text-sm text-right">{point.percentage.toFixed(0)}%</span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Empty state */}
            {summary && summary.vulnerability_trend.length === 0 && summary.mttr.every(m => m.count === 0) && (
                <div className="mt-6 bg-card border border-border rounded-lg p-12 text-center">
                    <TrendingUp className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                    <h3 className="text-lg font-medium mb-2">{t("noData")}</h3>
                    <p className="text-muted-foreground">
                        {t("noDataDescription")}
                    </p>
                </div>
            )}
        </div>
    );
}
