import { Windows7View } from "@/components/Windows7View";
import { Metadata } from "next";

export const metadata: Metadata = {
  title: "Windows 7 Aero Glass & CMD - PhishIntel.ai",
  description:
    "Interactive Windows 7 Aero Glass Security Shell and Command Prompt (cmd.exe) terminal for zero-network static phishing URL inspection.",
};

export default function Windows7Page() {
  return <Windows7View />;
}
