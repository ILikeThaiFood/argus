import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ARGUS | Cyber Threat Detection Platform",
  description: "AI-Powered Real-Time Cyber Threat Detection & Common Operating Picture",
  icons: { icon: "/favicon.ico" },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-navy-900 text-slate-200 font-mono antialiased">
        {children}
      </body>
    </html>
  );
}
