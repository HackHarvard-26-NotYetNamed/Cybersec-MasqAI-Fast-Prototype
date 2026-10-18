import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { SiteHeader } from "@/components/site/header";
import { SiteFooter } from "@/components/site/footer";
import { PitchMode } from "@/components/site/pitch-mode";
import { TooltipProvider } from "@/components/ui/tooltip";
import "./globals.css";

// Every page is a static showcase: no request-time rendering anywhere.
export const ensureStatic = "navigation";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: { default: "MasqAI: a local context firewall for AI agents", template: "%s · MasqAI" },
  description: "Your LLM key is a two-way mirror. MasqAI makes it one-way. A local context firewall for AI coding agents.",
  // Absolute URLs for the social card (app/opengraph-image.tsx).
  metadataBase: new URL("https://masqai.vercel.app"),
  openGraph: { type: "website", siteName: "MasqAI", url: "/" },
  twitter: { card: "summary_large_image" },
};

// Dark by default; a saved "light" choice is applied before paint to avoid a flash.
const THEME_SCRIPT = `try{if(localStorage.getItem("masq-theme")==="light")document.documentElement.classList.remove("dark")}catch(e){}`;

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`dark ${geistSans.variable} ${geistMono.variable} h-full antialiased`}
      suppressHydrationWarning
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body className="flex min-h-full flex-col">
        <TooltipProvider>
          <a
            href="#main"
            className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-card focus:px-4 focus:py-2"
          >
            Skip to content
          </a>
          <SiteHeader />
          <main id="main" className="flex-1">
            {children}
          </main>
          <SiteFooter />
          <PitchMode />
        </TooltipProvider>
      </body>
    </html>
  );
}
