import { ImageResponse } from "next/og";

export const runtime = "edge";
export const alt = "SBOMHub - SBOM Management Platform";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default async function OGImage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  const isJapanese = locale === "ja";

  const title = "SBOMHub";
  const subtitle = isJapanese
    ? "オープンソース SBOM 管理プラットフォーム"
    : "Open Source SBOM Management Platform";
  const features = isJapanese
    ? ["脆弱性管理", "VEX対応", "コンプライアンス", "CI/CD連携"]
    : ["Vulnerability Mgmt", "VEX Support", "Compliance", "CI/CD Integration"];

  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          alignItems: "center",
          background: "linear-gradient(135deg, #1e3a5f 0%, #2563eb 50%, #7c3aed 100%)",
          fontFamily: "sans-serif",
        }}
      >
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            padding: "60px",
          }}
        >
          {/* Shield icon placeholder */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              width: "80px",
              height: "80px",
              borderRadius: "20px",
              backgroundColor: "rgba(255,255,255,0.2)",
              marginBottom: "24px",
              fontSize: "40px",
            }}
          >
            🛡️
          </div>

          <div
            style={{
              fontSize: "72px",
              fontWeight: 800,
              color: "white",
              letterSpacing: "-2px",
              marginBottom: "16px",
            }}
          >
            {title}
          </div>

          <div
            style={{
              fontSize: "28px",
              color: "rgba(255,255,255,0.9)",
              marginBottom: "40px",
              textAlign: "center",
            }}
          >
            {subtitle}
          </div>

          <div
            style={{
              display: "flex",
              gap: "16px",
              flexWrap: "wrap",
              justifyContent: "center",
            }}
          >
            {features.map((feature) => (
              <div
                key={feature}
                style={{
                  display: "flex",
                  padding: "10px 24px",
                  borderRadius: "9999px",
                  backgroundColor: "rgba(255,255,255,0.15)",
                  border: "1px solid rgba(255,255,255,0.3)",
                  color: "white",
                  fontSize: "18px",
                }}
              >
                {feature}
              </div>
            ))}
          </div>
        </div>

        <div
          style={{
            position: "absolute",
            bottom: "30px",
            display: "flex",
            alignItems: "center",
            gap: "8px",
            color: "rgba(255,255,255,0.6)",
            fontSize: "16px",
          }}
        >
          sbomhub.app
        </div>
      </div>
    ),
    {
      ...size,
    }
  );
}
