import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#020617", // Slate 950
        card: "#0F172A",       // Slate 900
        border: "#1E293B",     // Slate 800
        primary: {
          DEFAULT: "#3B82F6",  // Blue 500
          hover: "#2563EB",
        },
        success: {
          DEFAULT: "#22C55E",  // Green 500
          bg: "rgba(34, 197, 94, 0.12)",
        },
        warning: {
          DEFAULT: "#F59E0B",  // Amber 500
          bg: "rgba(245, 158, 11, 0.12)",
        },
        danger: {
          DEFAULT: "#EF4444",  // Red 500
          bg: "rgba(239, 68, 68, 0.12)",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Consolas", "monospace"],
      },
      animation: {
        "pulse-subtle": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "fade-in": "fadeIn 0.3s cubic-bezier(0.16, 1, 0.3, 1)",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0", transform: "translateY(6px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
