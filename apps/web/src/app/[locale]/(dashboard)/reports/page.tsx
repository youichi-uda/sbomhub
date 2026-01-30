'use client';

import { useState, useEffect, useCallback } from 'react';
import { useTranslations, useLocale } from 'next-intl';
import { Loader2, FileText, Download, Plus, RefreshCw, Clock, CheckCircle2, AlertTriangle, Settings } from 'lucide-react';
import { api, GeneratedReport, ReportListResponse } from '@/lib/api';
import { useAuth } from '@clerk/nextjs';
import Link from 'next/link';

export default function ReportsPage() {
    const t = useTranslations("Reports");
    const tc = useTranslations("Common");
    const locale = useLocale();
    const { getToken } = useAuth();
    const [reports, setReports] = useState<GeneratedReport[]>([]);
    const [total, setTotal] = useState(0);
    const [page, setPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [loading, setLoading] = useState(true);
    const [generating, setGenerating] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Generate modal state
    const [showGenerateModal, setShowGenerateModal] = useState(false);
    const [generateInput, setGenerateInput] = useState({
        report_type: 'executive',
        format: 'pdf',
    });

    const loadReports = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const response: ReportListResponse = await api.reports.list(page, 20);
            setReports(response.reports || []);
            setTotal(response.total);
            setTotalPages(response.total_pages);
        } catch (err) {
            setError(t("loadFailed"));
            console.error(err);
        } finally {
            setLoading(false);
        }
    }, [page]);

    useEffect(() => {
        loadReports();
    }, [loadReports]);

    const handleGenerate = async () => {
        setGenerating(true);
        setError(null);
        try {
            await api.reports.generate(generateInput);
            setShowGenerateModal(false);
            // Refresh list after a short delay
            setTimeout(loadReports, 1000);
        } catch (err) {
            setError(t("generateFailed"));
            console.error(err);
        } finally {
            setGenerating(false);
        }
    };

    const handleDownload = async (report: GeneratedReport) => {
        try {
            const token = await getToken();
            const response = await fetch(api.reports.downloadUrl(report.id), {
                headers: {
                    'Authorization': `Bearer ${token}`,
                },
            });
            if (!response.ok) throw new Error('Download failed');

            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${report.title}.${report.format}`;
            document.body.appendChild(a);
            a.click();
            // Delay cleanup to ensure download starts
            setTimeout(() => {
                window.URL.revokeObjectURL(url);
                a.remove();
            }, 100);
        } catch (err) {
            setError(t("downloadFailed"));
            console.error(err);
        }
    };

    const formatDate = (dateStr: string) => {
        return new Date(dateStr).toLocaleString(locale === 'ja' ? 'ja-JP' : 'en-US');
    };

    const formatFileSize = (bytes: number) => {
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    };

    const getStatusIcon = (status: string) => {
        switch (status) {
            case 'completed':
            case 'emailed':
                return <CheckCircle2 className="w-5 h-5 text-green-500" />;
            case 'failed':
                return <AlertTriangle className="w-5 h-5 text-red-500" />;
            case 'generating':
                return <Loader2 className="w-5 h-5 text-blue-500 animate-spin" />;
            default:
                return <Clock className="w-5 h-5 text-muted-foreground" />;
        }
    };

    const getReportTypeLabel = (type: string) => {
        switch (type) {
            case 'executive': return t("executive");
            case 'technical': return t("technical");
            case 'compliance': return t("compliance");
            default: return type;
        }
    };

    if (loading && reports.length === 0) {
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
                    <Link
                        href={`/${locale}/settings/reports`}
                        className="flex items-center gap-2 px-4 py-2 border border-border rounded-lg hover:bg-muted transition-colors"
                    >
                        <Settings className="w-4 h-4" />
                        {t("settings")}
                    </Link>
                    <button
                        onClick={loadReports}
                        className="flex items-center gap-2 px-4 py-2 border border-border rounded-lg hover:bg-muted transition-colors"
                    >
                        <RefreshCw className="w-4 h-4" />
                        {t("refresh")}
                    </button>
                    <button
                        onClick={() => setShowGenerateModal(true)}
                        className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors"
                    >
                        <Plus className="w-4 h-4" />
                        {t("generate")}
                    </button>
                </div>
            </div>

            {error && (
                <div className="mb-6 p-4 bg-destructive/10 border border-destructive/20 rounded-lg text-destructive">
                    {error}
                </div>
            )}

            {/* Reports List */}
            <div className="bg-card border border-border rounded-lg overflow-hidden">
                {reports.length === 0 ? (
                    <div className="p-12 text-center">
                        <FileText className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                        <h3 className="text-lg font-medium mb-2">{t("noReports")}</h3>
                        <p className="text-muted-foreground mb-4">
                            {t("noReportsDescription")}
                        </p>
                        <button
                            onClick={() => setShowGenerateModal(true)}
                            className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors"
                        >
                            <Plus className="w-4 h-4" />
                            {t("generate")}
                        </button>
                    </div>
                ) : (
                    <table className="w-full">
                        <thead className="bg-muted/50">
                            <tr>
                                <th className="px-4 py-3 text-left text-sm font-medium">{t("status")}</th>
                                <th className="px-4 py-3 text-left text-sm font-medium">{t("reportTitle")}</th>
                                <th className="px-4 py-3 text-left text-sm font-medium">{t("type")}</th>
                                <th className="px-4 py-3 text-left text-sm font-medium">{t("period")}</th>
                                <th className="px-4 py-3 text-left text-sm font-medium">{t("size")}</th>
                                <th className="px-4 py-3 text-left text-sm font-medium">{t("createdAt")}</th>
                                <th className="px-4 py-3 text-left text-sm font-medium">{t("actions")}</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                            {reports.map((report) => (
                                <tr key={report.id} className="hover:bg-muted/30">
                                    <td className="px-4 py-3">
                                        <div className="flex items-center gap-2">
                                            {getStatusIcon(report.status)}
                                            <span className="text-sm capitalize">{report.status}</span>
                                        </div>
                                    </td>
                                    <td className="px-4 py-3 font-medium">{report.title}</td>
                                    <td className="px-4 py-3 text-sm">
                                        <span className="px-2 py-1 bg-muted rounded text-xs">
                                            {getReportTypeLabel(report.report_type)}
                                        </span>
                                    </td>
                                    <td className="px-4 py-3 text-sm text-muted-foreground">
                                        {new Date(report.period_start).toLocaleDateString('ja-JP')} -
                                        {new Date(report.period_end).toLocaleDateString('ja-JP')}
                                    </td>
                                    <td className="px-4 py-3 text-sm text-muted-foreground">
                                        {report.file_size > 0 ? formatFileSize(report.file_size) : '-'}
                                    </td>
                                    <td className="px-4 py-3 text-sm text-muted-foreground">
                                        {formatDate(report.created_at)}
                                    </td>
                                    <td className="px-4 py-3">
                                        {(report.status === 'completed' || report.status === 'emailed') && (
                                            <button
                                                onClick={() => handleDownload(report)}
                                                className="flex items-center gap-1 px-3 py-1 text-sm text-primary hover:bg-primary/10 rounded transition-colors"
                                            >
                                                <Download className="w-4 h-4" />
                                                {t("download")}
                                            </button>
                                        )}
                                        {report.status === 'failed' && report.error_message && (
                                            <span className="text-sm text-destructive" title={report.error_message}>
                                                {t("error")}
                                            </span>
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
                <div className="flex items-center justify-between mt-4">
                    <p className="text-sm text-muted-foreground">
                        {t("pageInfo", { total, start: ((page - 1) * 20) + 1, end: Math.min(page * 20, total) })}
                    </p>
                    <div className="flex items-center gap-2">
                        <button
                            onClick={() => setPage(p => Math.max(1, p - 1))}
                            disabled={page === 1}
                            className="px-3 py-2 border border-border rounded-lg hover:bg-muted disabled:opacity-50"
                        >
                            {t("previous")}
                        </button>
                        <span className="text-sm">{page} / {totalPages}</span>
                        <button
                            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                            disabled={page === totalPages}
                            className="px-3 py-2 border border-border rounded-lg hover:bg-muted disabled:opacity-50"
                        >
                            {t("next")}
                        </button>
                    </div>
                </div>
            )}

            {/* Generate Modal */}
            {showGenerateModal && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                    <div className="bg-card border border-border rounded-lg p-6 w-full max-w-md mx-4">
                        <h2 className="text-lg font-semibold mb-4">{t("generate")}</h2>

                        <div className="space-y-4">
                            <div>
                                <label className="block text-sm font-medium mb-2">{t("reportType")}</label>
                                <select
                                    value={generateInput.report_type}
                                    onChange={(e) => setGenerateInput(prev => ({ ...prev, report_type: e.target.value }))}
                                    className="w-full bg-background border border-border rounded-lg px-3 py-2"
                                >
                                    <option value="executive">{t("executive")}</option>
                                    <option value="technical">{t("technical")}</option>
                                    <option value="compliance">{t("compliance")}</option>
                                </select>
                            </div>

                            <div>
                                <label className="block text-sm font-medium mb-2">{t("format")}</label>
                                <select
                                    value={generateInput.format}
                                    onChange={(e) => setGenerateInput(prev => ({ ...prev, format: e.target.value }))}
                                    className="w-full bg-background border border-border rounded-lg px-3 py-2"
                                >
                                    <option value="pdf">PDF</option>
                                    <option value="xlsx">Excel</option>
                                </select>
                            </div>
                        </div>

                        <div className="flex justify-end gap-2 mt-6">
                            <button
                                onClick={() => setShowGenerateModal(false)}
                                className="px-4 py-2 border border-border rounded-lg hover:bg-muted transition-colors"
                            >
                                {tc("cancel")}
                            </button>
                            <button
                                onClick={handleGenerate}
                                disabled={generating}
                                className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50 transition-colors"
                            >
                                {generating ? (
                                    <>
                                        <Loader2 className="w-4 h-4 animate-spin" />
                                        {t("generating")}...
                                    </>
                                ) : (
                                    <>
                                        <Plus className="w-4 h-4" />
                                        {t("generate")}
                                    </>
                                )}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
