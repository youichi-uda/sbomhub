import { ImageResponse } from "next/og";

export const runtime = "edge";
export const alt = "SBOMHub - Privacy Policy";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default async function OGImage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  const isJapanese = locale === "ja";

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
            fontSize: "72px",
            fontWeight: 800,
            color: "white",
            letterSpacing: "-2px",
            marginBottom: "16px",
          }}
        >
          SBOMHub
        </div>
        <div
          style={{
            fontSize: "36px",
            color: "rgba(255,255,255,0.9)",
          }}
        >
          {isJapanese ? "プライバシーポリシー" : "Privacy Policy"}
        </div>
        <div
          style={{
            position: "absolute",
            bottom: "30px",
            color: "rgba(255,255,255,0.6)",
            fontSize: "16px",
          }}
        >
          sbomhub.app
        </div>
      </div>
    ),
    { ...size }
  );
}
