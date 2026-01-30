'use client';

import { useState, useEffect } from 'react';
import { Loader2, Save, ArrowLeft } from 'lucide-react';
import { api, ReportSettings } from '@/lib/api';
import Link from 'next/link';

const WEEKDAYS = ['日曜日', '月曜日', '火曜日', '水曜日', '木曜日', '金曜日', '土曜日'];
const HOURS = Array.from({ length: 24 }, (_, i) => i);

export default function ReportSettingsPage() {
    const [settings, setSettings] = useState<ReportSettings[]>([]);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState<string | null>(null);

    useEffect(() => {
        loadSettings();
    }, []);

    const loadSettings = async () => {
        setLoading(true);
        try {
            const data = await api.reports.getSettings() as ReportSettings[];
            setSettings(Array.isArray(data) ? data : [data]);
        } catch (err) {
            setError('設定の読み込みに失敗しました');
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

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
            setSuccess(`${getReportTypeLabel(setting.report_type)}の設定を保存しました`);
            setTimeout(() => setSuccess(null), 3000);
        } catch (err) {
            setError('設定の保存に失敗しました');
            console.error(err);
        } finally {
            setSaving(null);
        }
    };

    const updateSetting = (reportType: string, updates: Partial<ReportSettings>) => {
        setSettings(prev => prev.map(s =>
            s.report_type === reportType ? { ...s, ...updates } : s
        ));
    };

    const getReportTypeLabel = (type: string) => {
        switch (type) {
            case 'executive': return '経営レポート';
            case 'technical': return '技術レポート';
            case 'compliance': return 'コンプライアンスレポート';
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
                    href="/reports"
                    className="p-2 hover:bg-muted rounded-lg transition-colors"
                >
                    <ArrowLeft className="w-5 h-5" />
                </Link>
                <div>
                    <h1 className="text-2xl font-bold">レポート設定</h1>
                    <p className="text-sm text-muted-foreground mt-1">
                        自動レポート生成のスケジュールと配信設定
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
                                        <label className="block text-sm font-medium mb-2">スケジュール</label>
                                        <select
                                            value={setting.schedule_type}
                                            onChange={(e) => updateSetting(setting.report_type, { schedule_type: e.target.value })}
                                            className="w-full bg-background border border-border rounded-lg px-3 py-2"
                                        >
                                            <option value="weekly">毎週</option>
                                            <option value="monthly">毎月</option>
                                        </select>
                                    </div>

                                    <div>
                                        <label className="block text-sm font-medium mb-2">
                                            {setting.schedule_type === 'weekly' ? '曜日' : '日付'}
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
                                                    <option key={d} value={d}>{d}日</option>
                                                ))}
                                            </select>
                                        )}
                                    </div>
                                </div>

                                <div className="grid grid-cols-2 gap-4">
                                    <div>
                                        <label className="block text-sm font-medium mb-2">時間</label>
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
                                        <label className="block text-sm font-medium mb-2">フォーマット</label>
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
                                            <label className="font-medium">メール配信</label>
                                            <p className="text-sm text-muted-foreground">
                                                レポート生成後に自動でメール送信
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
                                                送信先メールアドレス（カンマ区切り）
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
                                                保存中...
                                            </>
                                        ) : (
                                            <>
                                                <Save className="w-4 h-4" />
                                                保存
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
