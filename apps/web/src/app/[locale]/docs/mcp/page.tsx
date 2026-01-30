"use client";

import { useTranslations } from "next-intl";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Copy, Check, Terminal, MessageSquare, GitBranch, Key, ExternalLink } from "lucide-react";
import { useState } from "react";
import Link from "next/link";

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Button variant="ghost" size="sm" onClick={handleCopy} className="h-6 w-6 p-0">
      {copied ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3" />}
    </Button>
  );
}

function CodeBlock({ children, copyable = true }: { children: string; copyable?: boolean }) {
  return (
    <div className="relative bg-slate-900 text-slate-100 rounded-lg p-4 font-mono text-sm overflow-x-auto">
      {copyable && (
        <div className="absolute top-2 right-2">
          <CopyButton text={children} />
        </div>
      )}
      <pre className="whitespace-pre-wrap">{children}</pre>
    </div>
  );
}

export default function MCPDocsPage() {
  const t = useTranslations("MCPDocs");

  const claudeConfig = `{
  "mcpServers": {
    "sbomhub": {
      "command": "node",
      "args": ["/path/to/sbomhub/packages/mcp-server/dist/index.js"],
      "env": {
        "SBOMHUB_API_URL": "https://your-sbomhub.app",
        "SBOMHUB_API_KEY": "sbh_your_api_key_here"
      }
    }
  }
}`;

  const cursorConfig = `{
  "mcpServers": {
    "sbomhub": {
      "command": "node",
      "args": ["/path/to/sbomhub/packages/mcp-server/dist/index.js"],
      "env": {
        "SBOMHUB_API_URL": "https://your-sbomhub.app",
        "SBOMHUB_API_KEY": "sbh_your_api_key_here"
      }
    }
  }
}`;

  const tools = [
    { name: "sbomhub_list_projects", description: t("toolListProjects") },
    { name: "sbomhub_get_dashboard", description: t("toolGetDashboard") },
    { name: "sbomhub_search_cve", description: t("toolSearchCve") },
    { name: "sbomhub_search_component", description: t("toolSearchComponent") },
    { name: "sbomhub_diff", description: t("toolDiff") },
    { name: "sbomhub_get_vulnerabilities", description: t("toolGetVulnerabilities") },
    { name: "sbomhub_get_compliance", description: t("toolGetCompliance") },
  ];

  return (
    <div className="container mx-auto py-8 px-4 max-w-4xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2">{t("title")}</h1>
        <p className="text-muted-foreground text-lg">{t("description")}</p>
      </div>

      {/* What is MCP */}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <MessageSquare className="h-5 w-5" />
            {t("whatIsMcp")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p>{t("whatIsMcpDescription")}</p>
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <p className="text-blue-800 font-medium">{t("whatIsMcpExample")}</p>
          </div>
        </CardContent>
      </Card>

      {/* Setup Steps */}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle>{t("setupSteps")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Step 1: Get API Key */}
          <div>
            <h3 className="text-lg font-semibold flex items-center gap-2 mb-3">
              <Badge variant="outline">1</Badge>
              <Key className="h-4 w-4" />
              {t("step1Title")}
            </h3>
            <ol className="list-decimal list-inside space-y-2 text-muted-foreground ml-4">
              <li>{t("step1Item1")}</li>
              <li>{t("step1Item2")}</li>
              <li>{t("step1Item3")}</li>
              <li>{t("step1Item4")}</li>
            </ol>
            <div className="mt-3">
              <Link href="/projects">
                <Button variant="outline" size="sm">
                  {t("goToProjects")}
                  <ExternalLink className="h-3 w-3 ml-2" />
                </Button>
              </Link>
            </div>
          </div>

          {/* Step 2: Build */}
          <div>
            <h3 className="text-lg font-semibold flex items-center gap-2 mb-3">
              <Badge variant="outline">2</Badge>
              <Terminal className="h-4 w-4" />
              {t("step2Title")}
            </h3>
            <CodeBlock>{`cd packages/mcp-server
pnpm install
pnpm build`}</CodeBlock>
          </div>

          {/* Step 3: Configure */}
          <div>
            <h3 className="text-lg font-semibold flex items-center gap-2 mb-3">
              <Badge variant="outline">3</Badge>
              <GitBranch className="h-4 w-4" />
              {t("step3Title")}
            </h3>

            <div className="space-y-4">
              <div>
                <h4 className="font-medium mb-2">Claude Desktop</h4>
                <p className="text-sm text-muted-foreground mb-2">
                  Windows: <code className="bg-muted px-1 rounded">%APPDATA%\Claude\claude_desktop_config.json</code>
                </p>
                <p className="text-sm text-muted-foreground mb-2">
                  macOS: <code className="bg-muted px-1 rounded">~/Library/Application Support/Claude/claude_desktop_config.json</code>
                </p>
                <CodeBlock>{claudeConfig}</CodeBlock>
              </div>

              <div>
                <h4 className="font-medium mb-2">Cursor</h4>
                <p className="text-sm text-muted-foreground mb-2">
                  {t("cursorConfigPath")}: <code className="bg-muted px-1 rounded">.cursor/mcp.json</code>
                </p>
                <CodeBlock>{cursorConfig}</CodeBlock>
              </div>
            </div>
          </div>

          {/* Step 4: Restart */}
          <div>
            <h3 className="text-lg font-semibold flex items-center gap-2 mb-3">
              <Badge variant="outline">4</Badge>
              {t("step4Title")}
            </h3>
            <p className="text-muted-foreground">{t("step4Description")}</p>
          </div>
        </CardContent>
      </Card>

      {/* Available Tools */}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle>{t("availableTools")}</CardTitle>
          <CardDescription>{t("availableToolsDescription")}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {tools.map((tool) => (
              <div key={tool.name} className="flex items-start gap-3 p-3 bg-muted/50 rounded-lg">
                <code className="text-sm font-mono bg-background px-2 py-1 rounded border whitespace-nowrap">
                  {tool.name}
                </code>
                <span className="text-muted-foreground text-sm">{tool.description}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Usage Examples */}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle>{t("usageExamples")}</CardTitle>
          <CardDescription>{t("usageExamplesDescription")}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <div className="p-3 bg-muted/50 rounded-lg">
              <p className="font-medium">{t("example1")}</p>
            </div>
            <div className="p-3 bg-muted/50 rounded-lg">
              <p className="font-medium">{t("example2")}</p>
            </div>
            <div className="p-3 bg-muted/50 rounded-lg">
              <p className="font-medium">{t("example3")}</p>
            </div>
            <div className="p-3 bg-muted/50 rounded-lg">
              <p className="font-medium">{t("example4")}</p>
            </div>
            <div className="p-3 bg-muted/50 rounded-lg">
              <p className="font-medium">{t("example5")}</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Troubleshooting */}
      <Card>
        <CardHeader>
          <CardTitle>{t("troubleshooting")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <h4 className="font-medium text-red-600">{t("error1Title")}</h4>
            <p className="text-sm text-muted-foreground">{t("error1Solution")}</p>
          </div>
          <div>
            <h4 className="font-medium text-red-600">{t("error2Title")}</h4>
            <p className="text-sm text-muted-foreground">{t("error2Solution")}</p>
          </div>
          <div>
            <h4 className="font-medium text-red-600">{t("error3Title")}</h4>
            <p className="text-sm text-muted-foreground">{t("error3Solution")}</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
