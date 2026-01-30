'use client';

import { useState, useEffect, useCallback } from 'react';
import { Download, Loader2, ChevronLeft, ChevronRight, Filter, X } from 'lucide-react';
import { api, AuditLog, AuditListResponse, AuditFilter, ActionInfo, ResourceTypeInfo } from '@/lib/api';
import { useAuth } from '@clerk/nextjs';

export default function AuditLogPage() {
    const { getToken } = useAuth();
    const [logs, setLogs] = useState<AuditLog[]>([]);
    const [total, setTotal] = useState(0);
    const [page, setPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    // Filter states
    const [showFilters, setShowFilters] = useState(false);
    const [actions, setActions] = useState<ActionInfo[]>([]);
    const [resourceTypes, setResourceTypes] = useState<ResourceTypeInfo[]>([]);
    const [filter, setFilter] = useState<AuditFilter>({
        page: 1,
        limit: 50,
    });

    const loadFilterOptions = useCallback(async () => {
        try {
            const [actionsData, resourceTypesData] = await Promise.all([
                api.auditLogs.getActions(),
                api.auditLogs.getResourceTypes(),
            ]);
            setActions(actionsData);
            setResourceTypes(resourceTypesData);
        } catch (err) {
            console.error('Failed to load filter options:', err);
        }
    }, []);

    const loadLogs = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const response: AuditListResponse = await api.auditLogs.list({
                ...filter,
                page,
            });
            setLogs(response.logs || []);
            setTotal(response.total);
            setTotalPages(response.total_pages);
        } catch (err) {
            setError('監査ログの読み込みに失敗しました');
            console.error(err);
        } finally {
            setLoading(false);
        }
    }, [filter, page]);

    useEffect(() => {
        loadFilterOptions();
    }, [loadFilterOptions]);

    useEffect(() => {
        loadLogs();
    }, [loadLogs]);

    const handleExport = async () => {
        try {
            const token = await getToken();
            const exportUrl = api.auditLogs.exportUrl(filter);
            const response = await fetch(exportUrl, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                },
            });
            if (!response.ok) throw new Error('Export failed');

            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `audit-logs-${new Date().toISOString().split('T')[0]}.csv`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
        } catch (err) {
            setError('エクスポートに失敗しました');
            console.error(err);
        }
    };

    const handleFilterChange = (key: keyof AuditFilter, value: string) => {
        setFilter(prev => ({
            ...prev,
            [key]: value || undefined,
        }));
        setPage(1);
    };

    const clearFilters = () => {
        setFilter({
            page: 1,
            limit: 50,
        });
        setPage(1);
    };

    const hasActiveFilters = filter.action || filter.resource_type || filter.start_date || filter.end_date;

    const formatDate = (dateStr: string) => {
        return new Date(dateStr).toLocaleString('ja-JP');
    };

    const getActionLabel = (action: string) => {
        const actionInfo = actions.find(a => a.action === action);
        return actionInfo?.label || action;
    };

    const getResourceTypeLabel = (type: string) => {
        const typeInfo = resourceTypes.find(t => t.type === type);
        return typeInfo?.label || type;
    };

    const getActionBadgeColor = (action: string) => {
        if (action.includes('deleted')) return 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400';
        if (action.includes('created')) return 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400';
        if (action.includes('updated')) return 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400';
        if (action.includes('viewed')) return 'bg-gray-100 text-gray-800 dark:bg-gray-900/30 dark:text-gray-400';
        return 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400';
    };

    if (loading && logs.length === 0) {
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
                    <h1 className="text-2xl font-bold">監査ログ</h1>
                    <p className="text-sm text-muted-foreground mt-1">
                        すべての操作履歴を確認できます（{total.toLocaleString()}件）
                    </p>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        onClick={() => setShowFilters(!showFilters)}
                        className={`flex items-center gap-2 px-4 py-2 border rounded-lg hover:bg-muted transition-colors ${
                            hasActiveFilters ? 'border-primary text-primary' : 'border-border'
                        }`}
                    >
                        <Filter className="w-4 h-4" />
                        フィルター
                        {hasActiveFilters && (
                            <span className="bg-primary text-primary-foreground text-xs px-1.5 py-0.5 rounded-full">
                                ON
                            </span>
                        )}
                    </button>
                    <button
                        onClick={handleExport}
                        className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors"
                    >
                        <Download className="w-4 h-4" />
                        CSVエクスポート
                    </button>
                </div>
            </div>

            {error && (
                <div className="mb-6 p-4 bg-destructive/10 border border-destructive/20 rounded-lg text-destructive">
                    {error}
                </div>
            )}

            {/* Filters */}
            {showFilters && (
                <div className="mb-6 p-4 bg-card border border-border rounded-lg">
                    <div className="flex items-center justify-between mb-4">
                        <h3 className="font-medium">フィルター条件</h3>
                        {hasActiveFilters && (
                            <button
                                onClick={clearFilters}
                                className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
                            >
                                <X className="w-4 h-4" />
                                クリア
                            </button>
                        )}
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        <div>
                            <label className="block text-sm font-medium mb-1">アクション</label>
                            <select
                                value={filter.action || ''}
                                onChange={(e) => handleFilterChange('action', e.target.value)}
                                className="w-full bg-background border border-border rounded-lg px-3 py-2"
                            >
                                <option value="">すべて</option>
                                {actions.map((action) => (
                                    <option key={action.action} value={action.action}>
                                        {action.label}
                                    </option>
                                ))}
                            </select>
                        </div>
                        <div>
                            <label className="block text-sm font-medium mb-1">リソースタイプ</label>
                            <select
                                value={filter.resource_type || ''}
                                onChange={(e) => handleFilterChange('resource_type', e.target.value)}
                                className="w-full bg-background border border-border rounded-lg px-3 py-2"
                            >
                                <option value="">すべて</option>
                                {resourceTypes.map((type) => (
                                    <option key={type.type} value={type.type}>
                                        {type.label}
                                    </option>
                                ))}
                            </select>
                        </div>
                        <div>
                            <label className="block text-sm font-medium mb-1">開始日</label>
                            <input
                                type="date"
                                value={filter.start_date || ''}
                                onChange={(e) => handleFilterChange('start_date', e.target.value)}
                                className="w-full bg-background border border-border rounded-lg px-3 py-2"
                            />
                        </div>
                        <div>
                            <label className="block text-sm font-medium mb-1">終了日</label>
                            <input
                                type="date"
                                value={filter.end_date || ''}
                                onChange={(e) => handleFilterChange('end_date', e.target.value)}
                                className="w-full bg-background border border-border rounded-lg px-3 py-2"
                            />
                        </div>
                    </div>
                </div>
            )}

            {/* Logs Table */}
            <div className="bg-card border border-border rounded-lg overflow-hidden">
                <div className="overflow-x-auto">
                    <table className="w-full">
                        <thead className="bg-muted/50">
                            <tr>
                                <th className="px-4 py-3 text-left text-sm font-medium">日時</th>
                                <th className="px-4 py-3 text-left text-sm font-medium">アクション</th>
                                <th className="px-4 py-3 text-left text-sm font-medium">リソース</th>
                                <th className="px-4 py-3 text-left text-sm font-medium">ユーザー</th>
                                <th className="px-4 py-3 text-left text-sm font-medium">IPアドレス</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                            {logs.length === 0 ? (
                                <tr>
                                    <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">
                                        監査ログがありません
                                    </td>
                                </tr>
                            ) : (
                                logs.map((log) => (
                                    <tr key={log.id} className="hover:bg-muted/30">
                                        <td className="px-4 py-3 text-sm whitespace-nowrap">
                                            {formatDate(log.created_at)}
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${getActionBadgeColor(log.action)}`}>
                                                {getActionLabel(log.action)}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3 text-sm">
                                            <span className="text-muted-foreground">
                                                {getResourceTypeLabel(log.resource_type)}
                                            </span>
                                            {log.resource_id && (
                                                <span className="ml-2 text-xs text-muted-foreground font-mono">
                                                    {log.resource_id.substring(0, 8)}...
                                                </span>
                                            )}
                                        </td>
                                        <td className="px-4 py-3 text-sm">
                                            {log.user_name || log.user_email || (
                                                <span className="text-muted-foreground">-</span>
                                            )}
                                        </td>
                                        <td className="px-4 py-3 text-sm font-mono text-muted-foreground">
                                            {log.ip_address || '-'}
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
                <div className="flex items-center justify-between mt-4">
                    <p className="text-sm text-muted-foreground">
                        {((page - 1) * (filter.limit || 50)) + 1} - {Math.min(page * (filter.limit || 50), total)} / {total} 件
                    </p>
                    <div className="flex items-center gap-2">
                        <button
                            onClick={() => setPage(p => Math.max(1, p - 1))}
                            disabled={page === 1}
                            className="flex items-center gap-1 px-3 py-2 border border-border rounded-lg hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            <ChevronLeft className="w-4 h-4" />
                            前へ
                        </button>
                        <span className="text-sm">
                            {page} / {totalPages}
                        </span>
                        <button
                            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                            disabled={page === totalPages}
                            className="flex items-center gap-1 px-3 py-2 border border-border rounded-lg hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            次へ
                            <ChevronRight className="w-4 h-4" />
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
}
