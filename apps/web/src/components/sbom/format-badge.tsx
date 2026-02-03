import { Badge } from "@/components/ui/badge";

interface FormatBadgeProps {
  format: string;
  version: string | null;
  className?: string;
}

export function FormatBadge({ format, version, className }: FormatBadgeProps) {
  const label = format === "cyclonedx" ? "CycloneDX" : "SPDX";
  return (
    <Badge variant="outline" className={`font-mono ${className || ""}`}>
      {label} {version || "?"}
    </Badge>
  );
}

export function formatSbomLabel(format: string, version: string | null): string {
  const label = format === "cyclonedx" ? "CycloneDX" : "SPDX";
  return version ? `${label} ${version}` : label;
}
