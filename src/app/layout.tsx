import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PhishIntel.ai — AI Powered Phishing URL Intelligence Platform",
  description:
    "Enterprise-grade static URL heuristic scanner, RFC 3986 component decomposition, and zero-network threat intelligence SOC dashboard.",
  keywords: [
    "cybersecurity",
    "phishing-detection",
    "threat-intelligence",
    "static-analysis",
    "rfc-3986",
    "soc-dashboard",
    "educational-security",
  ],
  authors: [{ name: "Manish Pundlik Patil", url: "https://github.com/ManishPatil2005" }],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-background text-foreground antialiased flex flex-col selection:bg-primary/30 selection:text-white">
        {children}
      </body>
    </html>
  );
}
