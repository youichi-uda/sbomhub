'use client';

import { useState, useEffect } from 'react';
import { Clock, Check, AlertTriangle, Loader2 } from 'lucide-react';
import { useApi } from '@/lib/api';

interface ScanSettings {
    id: string;
    enabled: boolean;
    schedule_type: 'hourly' | 'daily' | 'weekly';
    schedule_hour: number;
    schedule_day?: number;
    notify_critical: boolean;
    notify_high: boolean;
    notify_medium: boolean;
    notify_low: boolean;
    last_scan_at?: string;
    next_scan_at?: string;
}

interface ScanLog {
    id: string;
    started_at: string;
    completed_at?: string;
    status: 'pending' | 'running' | 'completed' | 'failed';
    projects_scanned: number;
    new_vulnerabilities: number;
    error_message?: string;
}

const WEEKDAYS = ['日曜日', '月曜日', '火曜日', '水曜日', '木曜日', '金曜日', '土曜日'];
const HOURS = Array.from({ length: 24 }, (_, i) => i);

export default function ScanSettingsPage() {
    const api = useApi();
    const [settings, setSettings] = useState<ScanSettings | null>(null);
    const [logs, setLogs] = useState<ScanLog[]>([]);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState(false);

    useEffect(() => {
        loadSettings();
        loadLogs();
    }, []);

    const loadSettings = async () => {
        try {
            const data = await api.get<ScanSettings>('/api/v1/settings/scan');
            setSettings(data);
        } catch (err) {
            setError('設定の読み込みに失敗しました');
        } finally {
            setLoading(false);
        }
    };

    const loadLogs = async () => {
        try {
            const data = await api.get<ScanLog[]>('/api/v1/settings/scan/logs?limit=10');
            setLogs(data || []);
        } catch (err) {
            // Ignore log loading errors
        }
    };

    const handleSave = async () => {
        if (!settings) return;

        setSaving(true);
        setError(null);
        setSuccess(false);

        try {
            const updated = await api.put<ScanSettings>('/api/v1/settings/scan', settings);
            setSettings(updated);
            setSuccess(true);
            setTimeout(() => setSuccess(false), 3000);
        } catch (err) {
            setError('設定の保存に失敗しました');
        } finally {
            setSaving(false);
        }
    };

    const updateSetting = <K extends keyof ScanSettings>(key: K, value: ScanSettings[K]) => {
        if (!settings) return;
        setSettings({ ...settings, [key]: value });
    };

    const formatDate = (dateStr: string) => {
        return new Date(dateStr).toLocaleString('ja-JP');
    };

    const getStatusIcon = (status: ScanLog['status']) => {
        switch (status) {
            case 'completed':
                return <Check className="w-4 h-4 text-green-500" />;
            case 'failed':
                return <AlertTriangle className="w-4 h-4 text-red-500" />;
            case 'running':
                return <Loader2 className="w-4 h-4 text-blue-500 animate-spin" />;
            default:
                return <Clock className="w-4 h-4 text-muted-foreground" />;
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
        <div className="max-w-2xl mx-auto py-8 px-4">
            <h1 className="text-2xl font-bold mb-6">定期スキャン設定</h1>

            {error && (
                <div className="mb-6 p-4 bg-destructive/10 border border-destructive/20 rounded-lg text-destructive">
                    {error}
                </div>
            )}

            {success && (
                <div className="mb-6 p-4 bg-green-500/10 border border-green-500/20 rounded-lg text-green-600 dark:text-green-400">
                    設定を保存しました
                </div>
            )}

            <div className="bg-card border border-border rounded-lg p-6 space-y-6">
                {/* Enable/Disable */}
                <div className="flex items-center justify-between">
                    <div>
                        <label className="font-medium">スキャン有効</label>
                        <p className="text-sm text-muted-foreground">
                            定期的に脆弱性データベースを確認します
                        </p>
                    </div>
                    <button
                        onClick={() => updateSetting('enabled', !settings?.enabled)}
                        className={`relative w-12 h-6 rounded-full transition-colors ${settings?.enabled ? 'bg-primary' : 'bg-muted'
                            }`}
                    >
                        <span
                            className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform ${settings?.enabled ? 'left-7' : 'left-1'
                                }`}
                        />
                    </button>
                </div>

                {/* Schedule Type */}
                <div>
                    <label className="block font-medium mb-2">スキャン間隔</label>
                    <div className="space-y-2">
                        {(['hourly', 'daily', 'weekly'] as const).map((type) => (
                            <label key={type} className="flex items-center gap-3 cursor-pointer">
                                <input
                                    type="radio"
                                    name="schedule_type"
                                    checked={settings?.schedule_type === type}
                                    onChange={() => updateSetting('schedule_type', type)}
                                    className="w-4 h-4 text-primary"
                                />
                                <span>
                                    {type === 'hourly' && '毎時'}
                                    {type === 'daily' && '毎日'}
                                    {type === 'weekly' && '毎週'}
                                </span>

                                {type === 'daily' && settings?.schedule_type === 'daily' && (
                                    <select
                                        value={settings.schedule_hour}
                                        onChange={(e) => updateSetting('schedule_hour', parseInt(e.target.value))}
                                        className="ml-2 bg-background border border-border rounded px-2 py-1"
                                    >
                                        {HOURS.map((h) => (
                                            <option key={h} value={h}>
                                                {h.toString().padStart(2, '0')}:00
                                            </option>
                                        ))}
                                    </select>
                                )}

                                {type === 'weekly' && settings?.schedule_type === 'weekly' && (
                                    <div className="flex gap-2 ml-2">
                                        <select
                                            value={settings.schedule_day ?? 1}
                                            onChange={(e) => updateSetting('schedule_day', parseInt(e.target.value))}
                                            className="bg-background border border-border rounded px-2 py-1"
                                        >
                                            {WEEKDAYS.map((day, i) => (
                                                <option key={i} value={i}>
                                                    {day}
                                                </option>
                                            ))}
                                        </select>
                                        <select
                                            value={settings.schedule_hour}
                                            onChange={(e) => updateSetting('schedule_hour', parseInt(e.target.value))}
                                            className="bg-background border border-border rounded px-2 py-1"
                                        >
                                            {HOURS.map((h) => (
                                                <option key={h} value={h}>
                                                    {h.toString().padStart(2, '0')}:00
                                                </option>
                                            ))}
                                        </select>
                                    </div>
                                )}
                            </label>
                        ))}
                    </div>
                </div>

                {/* Notification Settings */}
                <div>
                    <label className="block font-medium mb-2">通知条件</label>
                    <p className="text-sm text-muted-foreground mb-3">
                        選択した重大度以上の脆弱性が検出された場合に通知します
                    </p>
                    <div className="space-y-2">
                        {[
                            { key: 'notify_critical' as const, label: 'Critical', color: 'text-red-500' },
                            { key: 'notify_high' as const, label: 'High', color: 'text-orange-500' },
                            { key: 'notify_medium' as const, label: 'Medium', color: 'text-yellow-500' },
                            { key: 'notify_low' as const, label: 'Low', color: 'text-green-500' },
                        ].map(({ key, label, color }) => (
                            <label key={key} className="flex items-center gap-3 cursor-pointer">
                                <input
                                    type="checkbox"
                                    checked={settings?.[key] ?? false}
                                    onChange={(e) => updateSetting(key, e.target.checked)}
                                    className="w-4 h-4 text-primary rounded"
                                />
                                <span className={color}>{label}</span>
                            </label>
                        ))}
                    </div>
                </div>

                {/* Next Scan Info */}
                {settings?.next_scan_at && (
                    <div className="pt-4 border-t border-border">
                        <p className="text-sm text-muted-foreground">
                            次回スキャン: {formatDate(settings.next_scan_at)}
                        </p>
                    </div>
                )}

                {/* Save Button */}
                <div className="pt-4">
                    <button
                        onClick={handleSave}
                        disabled={saving}
                        className="w-full bg-primary text-primary-foreground py-2 rounded-lg font-medium hover:bg-primary/90 disabled:opacity-50"
                    >
                        {saving ? (
                            <Loader2 className="w-5 h-5 animate-spin mx-auto" />
                        ) : (
                            '保存'
                        )}
                    </button>
                </div>
            </div>

            {/* Scan Logs */}
            {logs.length > 0 && (
                <div className="mt-8">
                    <h2 className="text-lg font-semibold mb-4">スキャン履歴</h2>
                    <div className="bg-card border border-border rounded-lg overflow-hidden">
                        <table className="w-full">
                            <thead className="bg-muted/50">
                                <tr>
                                    <th className="px-4 py-2 text-left text-sm font-medium">ステータス</th>
                                    <th className="px-4 py-2 text-left text-sm font-medium">開始時刻</th>
                                    <th className="px-4 py-2 text-left text-sm font-medium">プロジェクト</th>
                                    <th className="px-4 py-2 text-left text-sm font-medium">新規脆弱性</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border">
                                {logs.map((log) => (
                                    <tr key={log.id}>
                                        <td className="px-4 py-3">
                                            <div className="flex items-center gap-2">
                                                {getStatusIcon(log.status)}
                                                <span className="text-sm capitalize">{log.status}</span>
                                            </div>
                                        </td>
                                        <td className="px-4 py-3 text-sm">
                                            {formatDate(log.started_at)}
                                        </td>
                                        <td className="px-4 py-3 text-sm">
                                            {log.projects_scanned}
                                        </td>
                                        <td className="px-4 py-3 text-sm">
                                            {log.new_vulnerabilities > 0 ? (
                                                <span className="text-orange-500 font-medium">
                                                    {log.new_vulnerabilities}
                                                </span>
                                            ) : (
                                                <span className="text-muted-foreground">0</span>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </div>
    );
}
