'use client';

import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslations, useLocale } from 'next-intl';
import { Loader2, Save, ArrowLeft } from 'lucide-react';
import { api, ReportSettings } from '@/lib/api';
import { queryKeys } from '@/lib/query/keys';
import { errorSlot, resolveErrorSlot, type ErrorSlot } from '@/lib/query/error-slot';
import Link from 'next/link';

const HOURS = Array.from({ length: 24 }, (_, i) => i);

export default function ReportSettingsPage() {
    const t = useTranslations("Settings.Reports");
    const tCommon = useTranslations("Common");
    const locale = useLocale();

    const WEEKDAYS = locale === 'ja'
        ? ['日曜日', '月曜日', '火曜日', '水曜日', '木曜日', '金曜日', '土曜日']
        : ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    const [saving, setSaving] = useState<string | null>(null);
    const [actionError, setActionError] = useState<ErrorSlot | null>(null);
    const [success, setSuccess] = useState<string | null>(null);

    const queryClient = useQueryClient();
    const settingsKey = queryKeys.reports.settings();
    const settingsQuery = useQuery({
        queryKey: settingsKey,
        queryFn: async (): Promise<ReportSettings[]> => {
            try {
                const data = await api.reports.getSettings() as ReportSettings[];
                return Array.isArray(data) ? data : [data];
            } catch (err) {
                console.error(err);
                throw err;
            }
        },
    });
    const loading = settingsQuery.isPending;
    // Load failures and save failures share one banner; a save clears it.
    const error = resolveErrorSlot(actionError, settingsKey, settingsQuery.errorUpdateCount, t('loadError'));
    const setError = (message: string | null) => setActionError(errorSlot(message, settingsKey, queryClient));
    // Per-row edits are a local draft over the server copy (the page only
    // ever saved row-by-row and never reloaded, so the draft is the list).
    const [draft, setDraft] = useState<ReportSettings[] | null>(null);
    const settings = draft ?? settingsQuery.data ?? [];

    const handleSave = async (setting: ReportSettings) => {
        setSaving(setting.report_type);
        setError(null);
        setSuccess(null);

        try {
            await api.reports.updateSettings({
                report_type: setting.report_type,
                enabled: setting.enabled,
                schedule_type: setting.schedule_type,
                schedule_day: setting.schedule_day,
                schedule_hour: setting.schedule_hour,
                format: setting.format,
                email_enabled: setting.email_enabled,
                email_recipients: setting.email_recipients,
                include_sections: setting.include_sections,
            });
            setSuccess(t('saveSuccess', { type: getReportTypeLabel(setting.report_type) }));
            setTimeout(() => setSuccess(null), 3000);
        } catch (err) {
            setError(t('saveError'));
            console.error(err);
        } finally {
            setSaving(null);
        }
    };

    const updateSetting = (reportType: string, updates: Partial<ReportSettings>) => {
        setDraft(prev => (prev ?? settingsQuery.data ?? []).map(s =>
            s.report_type === reportType ? { ...s, ...updates } : s
        ));
    };

    const getReportTypeLabel = (type: string) => {
        switch (type) {
            case 'executive': return t('executive');
            case 'technical': return t('technical');
            case 'compliance': return t('compliance');
            default: return type;
        }
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <Loader2 className="w-8 h-8 animate-spin text-primary" />
            </div>
        );
    }

    return (
        <div className="max-w-3xl mx-auto py-8 px-4">
            <div className="flex items-center gap-4 mb-6">
                <Link
                    href={`/${locale}/reports`}
                    className="p-2 hover:bg-muted rounded-lg transition-colors"
                >
                    <ArrowLeft className="w-5 h-5" />
                </Link>
                <div>
                    <h1 className="text-2xl font-bold">{t('title')}</h1>
                    <p className="text-sm text-muted-foreground mt-1">
                        {t('description')}
                    </p>
                </div>
            </div>

            {error && (
                <div className="mb-6 p-4 bg-destructive/10 border border-destructive/20 rounded-lg text-destructive">
                    {error}
                </div>
            )}

            {success && (
                <div className="mb-6 p-4 bg-green-500/10 border border-green-500/20 rounded-lg text-green-600 dark:text-green-400">
                    {success}
                </div>
            )}

            <div className="space-y-6">
                {settings.map((setting) => (
                    <div key={setting.report_type} className="bg-card border border-border rounded-lg p-6">
                        <div className="flex items-center justify-between mb-4">
                            <h2 className="text-lg font-semibold">{getReportTypeLabel(setting.report_type)}</h2>
                            <button
                                onClick={() => updateSetting(setting.report_type, { enabled: !setting.enabled })}
                                className={`relative w-12 h-6 rounded-full transition-colors ${setting.enabled ? 'bg-primary' : 'bg-muted'}`}
                            >
                                <span
                                    className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform ${setting.enabled ? 'left-7' : 'left-1'}`}
                                />
                            </button>
                        </div>

                        {setting.enabled && (
                            <div className="space-y-4">
                                {/* Schedule Type */}
                                <div className="grid grid-cols-2 gap-4">
                                    <div>
                                        <label className="block text-sm font-medium mb-2">{t('schedule')}</label>
                                        <select
                                            value={setting.schedule_type}
                                            onChange={(e) => updateSetting(setting.report_type, { schedule_type: e.target.value })}
                                            className="w-full bg-background border border-border rounded-lg px-3 py-2"
                                        >
                                            <option value="weekly">{t('weekly')}</option>
                                            <option value="monthly">{t('monthly')}</option>
                                        </select>
                                    </div>

                                    <div>
                                        <label className="block text-sm font-medium mb-2">
                                            {setting.schedule_type === 'weekly' ? t('dayOfWeek') : t('dayOfMonth')}
                                        </label>
                                        {setting.schedule_type === 'weekly' ? (
                                            <select
                                                value={setting.schedule_day}
                                                onChange={(e) => updateSetting(setting.report_type, { schedule_day: parseInt(e.target.value) })}
                                                className="w-full bg-background border border-border rounded-lg px-3 py-2"
                                            >
                                                {WEEKDAYS.map((day, i) => (
                                                    <option key={i} value={i}>{day}</option>
                                                ))}
                                            </select>
                                        ) : (
                                            <select
                                                value={setting.schedule_day}
                                                onChange={(e) => updateSetting(setting.report_type, { schedule_day: parseInt(e.target.value) })}
                                                className="w-full bg-background border border-border rounded-lg px-3 py-2"
                                            >
                                                {Array.from({ length: 28 }, (_, i) => i + 1).map(d => (
                                                    <option key={d} value={d}>{locale === 'ja' ? `${d}日` : d}</option>
                                                ))}
                                            </select>
                                        )}
                                    </div>
                                </div>

                                <div className="grid grid-cols-2 gap-4">
                                    <div>
                                        <label className="block text-sm font-medium mb-2">{t('time')}</label>
                                        <select
                                            value={setting.schedule_hour}
                                            onChange={(e) => updateSetting(setting.report_type, { schedule_hour: parseInt(e.target.value) })}
                                            className="w-full bg-background border border-border rounded-lg px-3 py-2"
                                        >
                                            {HOURS.map(h => (
                                                <option key={h} value={h}>{h.toString().padStart(2, '0')}:00</option>
                                            ))}
                                        </select>
                                    </div>

                                    <div>
                                        <label className="block text-sm font-medium mb-2">{t('format')}</label>
                                        <select
                                            value={setting.format}
                                            onChange={(e) => updateSetting(setting.report_type, { format: e.target.value })}
                                            className="w-full bg-background border border-border rounded-lg px-3 py-2"
                                        >
                                            <option value="pdf">PDF</option>
                                            <option value="xlsx">Excel</option>
                                        </select>
                                    </div>
                                </div>

                                {/* Email Settings */}
                                <div className="pt-4 border-t border-border">
                                    <div className="flex items-center justify-between mb-4">
                                        <div>
                                            <label className="font-medium">{t('emailDelivery')}</label>
                                            <p className="text-sm text-muted-foreground">
                                                {t('emailDeliveryDescription')}
                                            </p>
                                        </div>
                                        <button
                                            onClick={() => updateSetting(setting.report_type, { email_enabled: !setting.email_enabled })}
                                            className={`relative w-10 h-5 rounded-full transition-colors ${setting.email_enabled ? 'bg-primary' : 'bg-muted'}`}
                                        >
                                            <span
                                                className={`absolute top-0.5 w-4 h-4 bg-white rounded-full transition-transform ${setting.email_enabled ? 'left-5' : 'left-0.5'}`}
                                            />
                                        </button>
                                    </div>

                                    {setting.email_enabled && (
                                        <div>
                                            <label className="block text-sm font-medium mb-2">
                                                {t('emailRecipients')}
                                            </label>
                                            <input
                                                type="text"
                                                value={setting.email_recipients?.join(', ') || ''}
                                                onChange={(e) => updateSetting(setting.report_type, {
                                                    email_recipients: e.target.value.split(',').map(s => s.trim()).filter(Boolean)
                                                })}
                                                placeholder="user@example.com, user2@example.com"
                                                className="w-full bg-background border border-border rounded-lg px-3 py-2"
                                            />
                                        </div>
                                    )}
                                </div>

                                {/* Save Button */}
                                <div className="pt-4">
                                    <button
                                        onClick={() => handleSave(setting)}
                                        disabled={saving === setting.report_type}
                                        className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50 transition-colors"
                                    >
                                        {saving === setting.report_type ? (
                                            <>
                                                <Loader2 className="w-4 h-4 animate-spin" />
                                                {t('saving')}
                                            </>
                                        ) : (
                                            <>
                                                <Save className="w-4 h-4" />
                                                {tCommon('save')}
                                            </>
                                        )}
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>
                ))}
            </div>
        </div>
    );
}
