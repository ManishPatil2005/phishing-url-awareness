"use client";

import React, { useState } from "react";
import { GraduationCap, CheckCircle2, XCircle, RotateCcw, X, Award } from "lucide-react";

interface Question {
  id: number;
  question: string;
  options: string[];
  correctIndex: number;
  explanation: string;
}

const QUIZ_QUESTIONS: Question[] = [
  {
    id: 1,
    question: "In the URL 'http://google.com@attacker-portal.invalid/login', where will the browser actually navigate?",
    options: [
      "google.com because it appears first",
      "attacker-portal.invalid because everything before '@' is treated as user authentication credentials",
      "Nowhere, modern browsers refuse to parse the '@' character",
      "Both servers simultaneously in a proxy tunnel",
    ],
    correctIndex: 1,
    explanation:
      "Pursuant to RFC 3986 §3.2.1, text preceding the '@' character in the authority component represents userinfo credentials. Browsers ignore the username and navigate directly to the host specified AFTER the '@' symbol.",
  },
  {
    id: 2,
    question: "What makes the domain 'paypaI.com' (with a capital 'I') an effective phishing lure?",
    options: [
      "Capital letters bypass standard internet DNS lookups",
      "In standard sans-serif fonts, uppercase 'I' (capital i) is visually indistinguishable from lowercase 'l' (el)",
      "It automatically forwards to the authentic PayPal app",
      "It requires a special security certificate to register",
    ],
    correctIndex: 1,
    explanation:
      "This is a visual homoglyph / typosquatting attack exploiting typography. In fonts like Arial or Segoe UI, uppercase 'I' and lowercase 'l' appear virtually identical, concealing the attacker's registration.",
  },
  {
    id: 3,
    question: "Why does Threat Engine v2.0 enforce the 'Non-Negative Invariance' rule that a score of 0 NEVER means 'Safe'?",
    options: [
      "The engine is incomplete and cannot detect threats reliably",
      "Static text analysis cannot inspect live web page contents, server-side payload delivery, or compromised legitimate accounts",
      "All websites on the internet are considered malicious by default",
      "It is a legal disclaimer required by ICANN",
    ],
    correctIndex: 1,
    explanation:
      "Static syntactic analysis evaluates lexical patterns in the URL string without network traffic. A compromised legitimate website or a newly registered domain without obvious keywords can still deliver malware. A score of 0 denotes absence of detectable syntactic anomalies, not proof of safety.",
  },
  {
    id: 4,
    question: "How do attackers exploit the '.zip' and '.mov' top-level domains?",
    options: [
      "They automatically unzip files onto the victim's hard drive",
      "They conflate filenames (e.g. 'invoice.zip') with clickable web destinations in chats and email clients",
      "They allow unencrypted data transmission without SSL",
      "They bypass all corporate firewalls automatically",
    ],
    correctIndex: 1,
    explanation:
      "Because '.zip' and '.mov' are common file archive extensions, sending text like 'Download invoice.zip' causes email and messaging applications to auto-hyperlink it as a website, redirecting the user to a web portal instead of opening a local document.",
  },
  {
    id: 5,
    question: "Why is submitting authentication credentials over plain HTTP considered high risk?",
    options: [
      "HTTP websites load too slowly",
      "HTTP transmits passwords in unencrypted plaintext, allowing any intermediary on the Wi-Fi or network path to eavesdrop on the credentials",
      "Google Chrome blocks all HTTP websites completely",
      "HTTP does not support user accounts",
    ],
    correctIndex: 1,
    explanation:
      "Unlike HTTPS which encrypts traffic using Transport Layer Security (TLS), plain HTTP transmits all headers, cookies, and form bodies in cleartext across the local network and internet routing hops.",
  },
];

interface EducationalQuizModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function EducationalQuizModal({ isOpen, onClose }: EducationalQuizModalProps) {
  const [currentIdx, setCurrentIdx] = useState(0);
  const [selectedOption, setSelectedOption] = useState<number | null>(null);
  const [isAnswered, setIsAnswered] = useState(false);
  const [score, setScore] = useState(0);
  const [isComplete, setIsComplete] = useState(false);

  if (!isOpen) return null;

  const currentQ = QUIZ_QUESTIONS[currentIdx];

  const handleSelectOption = (idx: number) => {
    if (isAnswered) return;
    setSelectedOption(idx);
    setIsAnswered(true);

    if (idx === currentQ.correctIndex) {
      setScore((prev) => prev + 1);
    }
  };

  const handleNext = () => {
    if (currentIdx + 1 < QUIZ_QUESTIONS.length) {
      setCurrentIdx((prev) => prev + 1);
      setSelectedOption(null);
      setIsAnswered(false);
    } else {
      setIsComplete(true);
    }
  };

  const handleRestart = () => {
    setCurrentIdx(0);
    setSelectedOption(null);
    setIsAnswered(false);
    setScore(0);
    setIsComplete(false);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="max-w-xl w-full rounded-2xl border border-border bg-card p-6 shadow-2xl space-y-5 text-foreground relative animate-in fade-in zoom-in-95">
        
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-border">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
              <GraduationCap className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100">Cybersecurity Phishing Awareness Quiz</h3>
              <p className="text-[11px] text-slate-400">Internship Skill Assessment & Educational Training</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Quiz Body */}
        {!isComplete ? (
          <div className="space-y-4">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Question {currentIdx + 1} of {QUIZ_QUESTIONS.length}</span>
              <span>Score: {score}</span>
            </div>

            <h4 className="text-sm font-semibold text-slate-100 leading-snug">{currentQ.question}</h4>

            {/* Options */}
            <div className="space-y-2">
              {currentQ.options.map((opt, i) => {
                let btnStyle = "border-border bg-slate-900/60 hover:bg-slate-800/80 text-slate-200";

                if (isAnswered) {
                  if (i === currentQ.correctIndex) {
                    btnStyle = "border-emerald-500/50 bg-emerald-500/10 text-emerald-300 font-semibold";
                  } else if (i === selectedOption) {
                    btnStyle = "border-red-500/50 bg-red-500/10 text-red-300";
                  } else {
                    btnStyle = "border-border bg-slate-950/40 text-slate-500 opacity-60";
                  }
                }

                return (
                  <button
                    key={i}
                    onClick={() => handleSelectOption(i)}
                    disabled={isAnswered}
                    className={`w-full text-left p-3 rounded-xl border text-xs transition-all flex items-start gap-2.5 cursor-pointer ${btnStyle}`}
                  >
                    <span className="font-mono font-bold shrink-0">{String.fromCharCode(65 + i)}.</span>
                    <span className="flex-1">{opt}</span>
                    {isAnswered && i === currentQ.correctIndex && (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    )}
                    {isAnswered && i === selectedOption && i !== currentQ.correctIndex && (
                      <XCircle className="w-4 h-4 text-red-400 shrink-0" />
                    )}
                  </button>
                );
              })}
            </div>

            {/* Explanation */}
            {isAnswered && (
              <div className="p-3.5 rounded-xl border border-primary/20 bg-primary/5 text-xs text-slate-300 space-y-1 animate-fade-in">
                <span className="font-bold text-primary">Technical Explanation:</span>
                <p className="text-[11px] leading-relaxed text-slate-300">{currentQ.explanation}</p>
              </div>
            )}

            {/* Next Button */}
            {isAnswered && (
              <div className="flex justify-end pt-2">
                <button
                  onClick={handleNext}
                  className="px-5 py-2 rounded-xl bg-primary hover:bg-blue-600 text-white font-bold text-xs shadow-md transition-all cursor-pointer"
                >
                  {currentIdx + 1 < QUIZ_QUESTIONS.length ? "Next Question →" : "View Final Results →"}
                </button>
              </div>
            )}
          </div>
        ) : (
          /* Completion Screen */
          <div className="text-center py-6 space-y-4">
            <div className="w-16 h-16 rounded-2xl bg-primary/10 border border-primary/30 flex items-center justify-center text-primary mx-auto">
              <Award className="w-8 h-8" />
            </div>
            <div>
              <h4 className="text-lg font-bold text-slate-100">Assessment Complete!</h4>
              <p className="text-xs text-slate-400 mt-1">
                You scored <strong className="text-primary font-bold text-sm">{score}</strong> out of{" "}
                <strong>{QUIZ_QUESTIONS.length}</strong> ({Math.round((score / QUIZ_QUESTIONS.length) * 100)}%).
              </p>
            </div>

            <div className="p-4 rounded-xl border border-border bg-slate-950 text-xs text-slate-300 text-left space-y-1.5">
              <span className="font-bold text-slate-200">Key Takeaway for Cyber Analysts:</span>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                Always evaluate URLs from right-to-left before the first path slash. Never rely on brand names appearing
                before the &apos;@&apos; delimiter or in deep subdomains.
              </p>
            </div>

            <div className="flex items-center justify-center gap-3 pt-2">
              <button
                onClick={handleRestart}
                className="px-4 py-2 rounded-xl border border-slate-700 bg-slate-800 text-slate-200 text-xs font-semibold flex items-center gap-1.5 cursor-pointer hover:bg-slate-700"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Retake Quiz</span>
              </button>
              <button
                onClick={onClose}
                className="px-5 py-2 rounded-xl bg-primary hover:bg-blue-600 text-white font-bold text-xs shadow-md cursor-pointer"
              >
                Return to SOC Dashboard
              </button>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
