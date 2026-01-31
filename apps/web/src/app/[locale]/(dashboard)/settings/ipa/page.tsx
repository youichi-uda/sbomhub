"use client";

import { useState, useEffect } from "react";
import { useTranslations, useLocale } from "next-intl";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { api, IPASyncSettings } from "@/lib/api";
import { RefreshCw, Shield, Bell, AlertTriangle, AlertCircle, Info } from "lucide-react";
import { Badge } from "@/components/ui/badge";

const SEVERITY_OPTIONS = [
  { value: "CRITICAL", label: "Critical", icon: AlertTriangle, color: "text-red-600" },
  { value: "HIGH", label: "High", icon: AlertCircle, color: "text-orange-600" },
  { value: "MEDIUM", label: "Medium", icon: AlertCircle, color: "text-yellow-600" },
  { value: "LOW", label: "Low", icon: Info, color: "text-blue-600" },
  { value: "INFO", label: "Info", icon: Info, color: "text-gray-600" },
];

export default function IPASettingsPage() {
  const t = useTranslations("Settings.IPA");
  const tCommon = useTranslations("Common");
  const locale = useLocale();
  const [settings, setSettings] = useState<IPASyncSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<{ new: number; updated: number } | null>(null);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      const data = await api.ipa.getSettings();
      setSettings(data);
    } catch (error) {
      console.error("Failed to load IPA settings:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    if (!settings) return;

    setSaving(true);
    try {
      const updated = await api.ipa.updateSettings({
        enabled: settings.enabled,
        notify_on_new: settings.notify_on_new,
        notify_severity: settings.notify_severity,
      });
      setSettings(updated);
    } catch (error) {
      console.error("Failed to save IPA settings:", error);
    } finally {
      setSaving(false);
    }
  };

  const handleSync = async () => {
    setSyncing(true);
    setSyncResult(null);
    try {
      const result = await api.ipa.sync();
      setSyncResult({
        new: result.new_announcements,
        updated: result.updated_announcements,
      });
    } catch (error) {
      console.error("Failed to sync IPA:", error);
    } finally {
      setSyncing(false);
    }
  };

  const toggleSeverity = (severity: string) => {
    if (!settings) return;

    const current = settings.notify_severity || [];
    const updated = current.includes(severity)
      ? current.filter((s) => s !== severity)
      : [...current, severity];

    setSettings({ ...settings, notify_severity: updated });
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">{t('title')}</h1>
        <p className="text-muted-foreground">
          {t('description')}
        </p>
      </div>

      <div className="grid gap-6">
        {/* Sync Settings */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              {t('syncSettings')}
            </CardTitle>
            <CardDescription>
              {t('syncSettingsDescription')}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label htmlFor="enabled">{t('enableAutoSync')}</Label>
                <p className="text-sm text-muted-foreground">
                  {t('autoSyncInterval')}
                </p>
              </div>
              <Switch
                id="enabled"
                checked={settings?.enabled ?? true}
                onCheckedChange={(checked) =>
                  setSettings(settings ? { ...settings, enabled: checked } : null)
                }
              />
            </div>

            {settings?.last_sync_at && (
              <div className="text-sm text-muted-foreground">
                {t('lastSync')}: {new Date(settings.last_sync_at).toLocaleString(locale === 'ja' ? "ja-JP" : "en-US")}
              </div>
            )}

            <div className="flex items-center gap-4">
              <Button onClick={handleSync} disabled={syncing} variant="outline">
                <RefreshCw className={`h-4 w-4 mr-2 ${syncing ? "animate-spin" : ""}`} />
                {syncing ? t('syncing') : t('syncNow')}
              </Button>

              {syncResult && (
                <div className="text-sm">
                  <Badge variant="secondary">{t('new')}: {syncResult.new}</Badge>
                  <Badge variant="outline" className="ml-2">{t('updated')}: {syncResult.updated}</Badge>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Notification Settings */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Bell className="h-5 w-5" />
              {t('notificationSettings')}
            </CardTitle>
            <CardDescription>
              {t('notificationSettingsDescription')}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label htmlFor="notify">{t('notifyOnNew')}</Label>
                <p className="text-sm text-muted-foreground">
                  {t('notifyOnNewDescription')}
                </p>
              </div>
              <Switch
                id="notify"
                checked={settings?.notify_on_new ?? true}
                onCheckedChange={(checked) =>
                  setSettings(settings ? { ...settings, notify_on_new: checked } : null)
                }
              />
            </div>

            <div className="space-y-3">
              <Label>{t('notifySeverityLevel')}</Label>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                {SEVERITY_OPTIONS.map((option) => {
                  const Icon = option.icon;
                  const isChecked = settings?.notify_severity?.includes(option.value) ?? false;

                  return (
                    <div
                      key={option.value}
                      className="flex items-center space-x-2"
                    >
                      <Checkbox
                        id={`severity-${option.value}`}
                        checked={isChecked}
                        onCheckedChange={() => toggleSeverity(option.value)}
                        disabled={!settings?.notify_on_new}
                      />
                      <label
                        htmlFor={`severity-${option.value}`}
                        className={`text-sm font-medium cursor-pointer flex items-center gap-1 ${option.color}`}
                      >
                        <Icon className="h-4 w-4" />
                        {option.label}
                      </label>
                    </div>
                  );
                })}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Information Sources */}
        <Card>
          <CardHeader>
            <CardTitle>{t('informationSources')}</CardTitle>
            <CardDescription>
              {t('informationSourcesDescription')}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-start gap-4 p-4 rounded-lg border">
                <Shield className="h-8 w-8 text-blue-600 flex-shrink-0" />
                <div>
                  <h4 className="font-medium">{t('ipaSecurityAlert')}</h4>
                  <p className="text-sm text-muted-foreground mt-1">
                    {t('ipaSecurityAlertDescription')}
                  </p>
                  <a
                    href="https://www.ipa.go.jp/security/alert/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-primary hover:underline mt-2 inline-block"
                  >
                    {t('viewDetails')} →
                  </a>
                </div>
              </div>

              <div className="flex items-start gap-4 p-4 rounded-lg border">
                <Shield className="h-8 w-8 text-green-600 flex-shrink-0" />
                <div>
                  <h4 className="font-medium">{t('jvnVulnerabilityInfo')}</h4>
                  <p className="text-sm text-muted-foreground mt-1">
                    {t('jvnVulnerabilityInfoDescription')}
                  </p>
                  <a
                    href="https://jvndb.jvn.jp/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-primary hover:underline mt-2 inline-block"
                  >
                    {t('viewDetails')} →
                  </a>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Save Button */}
      <div className="flex justify-end">
        <Button onClick={handleSave} disabled={saving}>
          {saving ? t('saving') : t('saveSettings')}
        </Button>
      </div>
    </div>
  );
}
