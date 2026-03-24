"use client";
import { useState } from "react";
import {
  Upload,
  FileCode,
  ShieldAlert,
  ShieldCheck,
  CheckCircle,
  Activity,
  Terminal,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Crosshair,
  Info,
  Search,
  Database,
} from "lucide-react";
import ReactMarkdown from "react-markdown";

// Severity badge colors
function severityColor(severity: string) {
  const s = severity?.toLowerCase() || "";
  if (s === "critical") return "bg-red-600 text-white";
  if (s === "high") return "bg-orange-600 text-white";
  if (s === "medium") return "bg-amber-600 text-white";
  if (s === "low") return "bg-sky-600 text-white";
  return "bg-slate-600 text-white";
}

// Slither warning color based on severity level in the warning string
function slitherWarningStyle(warning: string) {
  const w = warning.toLowerCase();
  if (w.startsWith("[high]"))
    return "text-orange-200 bg-orange-900/20 border-l-2 border-orange-500";
  if (w.startsWith("[medium]"))
    return "text-amber-200 bg-amber-900/15 border-l-2 border-amber-500";
  if (w.startsWith("[low]"))
    return "text-sky-200 bg-sky-900/15 border-l-2 border-sky-500";
  // Informational or other
  return "text-slate-400 bg-slate-800/40 border-l-2 border-slate-600";
}

export default function Home() {
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [steps, setSteps] = useState<{label: string; status: "pending"|"running"|"done"|"error"}[]>([]);
  const [showReasoning, setShowReasoning] = useState(false);
  const [showSlither, setShowSlither] = useState(false);
  const [showRag, setShowRag] = useState(false);
  const [elapsedTime, setElapsedTime] = useState<number | null>(null);

  const PIPELINE_STEPS = [
    "Upload & Parse Contract",
    "AST Function Extraction (tree-sitter)",
    "Slither Static Analysis",
    "RAG Knowledge Base Search (CodeRankEmbed)",
    "Cross-Encoder Reranking + CRAG Gate",
    "LLM Deep Analysis",
  ];

  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async () => {
    if (!file) return alert("Please select a Solidity file!");

    if (!file.name.endsWith(".sol")) {
      alert("Invalid file type! Only .sol files are accepted.");
      return;
    }

    // Validate file size on client side (5MB limit, matching backend)
    const MAX_FILE_SIZE = 5 * 1024 * 1024;
    if (file.size > MAX_FILE_SIZE) {
      alert(`File too large (${(file.size / (1024 * 1024)).toFixed(1)}MB). Maximum: 5MB.`);
      return;
    }

    setLoading(true);
    setResult(null);
    setError(null);
    setElapsedTime(null);
    setShowReasoning(false);
    setShowSlither(false);
    setShowRag(false);

    // Init all steps as pending, then start first
    const initSteps = PIPELINE_STEPS.map((label, i) => ({
      label,
      status: (i === 0 ? "running" : "pending") as "pending"|"running"|"done"|"error",
    }));
    setSteps(initSteps);

    const formData = new FormData();
    formData.append("file", file);
    const startTime = Date.now();

    // Adaptive pipeline progress simulation
    // Each step has a realistic estimated duration (in ms) based on actual pipeline timing
    // Total ~35-45s: Upload(1s) + AST(2s) + Slither(8s) + RAG(5s) + Rerank(3s) + LLM(20s)
    const stepDurations = [1000, 2000, 8000, 5000, 3000, 20000];
    let stepIdx = 0;
    let stepTimer: ReturnType<typeof setTimeout> | null = null;

    const advanceStep = () => {
      stepIdx++;
      if (stepIdx < PIPELINE_STEPS.length) {
        setSteps(prev => prev.map((s, i) => {
          if (i < stepIdx) return { ...s, status: "done" };
          if (i === stepIdx) return { ...s, status: "running" };
          return s;
        }));
        stepTimer = setTimeout(advanceStep, stepDurations[stepIdx] || 5000);
      }
    };
    stepTimer = setTimeout(advanceStep, stepDurations[0] || 2000);

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
      const res = await fetch(`${apiUrl}/analyze`, {
        method: "POST",
        body: formData,
      });

      if (stepTimer) clearTimeout(stepTimer);

      if (!res.ok) {
        const errData = await res.json().catch(() => ({ detail: `Server error (${res.status})` }));
        throw new Error(errData.detail || `Server error: ${res.status}`);
      }

      const data = await res.json();
      setElapsedTime(Math.round((Date.now() - startTime) / 1000));

      // Mark all steps as done
      setSteps(prev => prev.map(s => ({ ...s, status: "done" })));
      setResult(data);
    } catch (err: any) {
      if (stepTimer) clearTimeout(stepTimer);

      const errorMessage = err.message === "Failed to fetch"
        ? `Cannot connect to backend server. Please ensure the backend is running at ${process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000"}`
        : err.message || "An unexpected error occurred.";

      setError(errorMessage);
      setElapsedTime(Math.round((Date.now() - startTime) / 1000));
      setSteps(prev => prev.map((s) => {
        if (s.status === "running") return { ...s, status: "error" };
        if (s.status === "pending") return s;
        return s;
      }));
    } finally {
      setLoading(false);
    }
  };

  // Extract structured data
  const structured = result?.ai_analysis_structured;
  const verdict = structured?.verdict || result?.llm_analysis?.verdict || "UNKNOWN";
  const confidence = structured?.confidence || "N/A";
  const primary = structured?.primary_vulnerability || null;
  const secondaries: any[] = structured?.secondary_warnings || [];
  const reasoning = structured?.reasoning || "";
  const isSafe = verdict === "SAFE";

  return (
    <div className="min-h-screen bg-[#0a0e1a] text-slate-200 p-6 font-sans">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <header className="mb-8 flex items-center justify-between border-b border-slate-800/60 pb-4">
          <h1 className="text-2xl font-bold text-blue-400 flex items-center gap-2">
            <ShieldAlert className="w-8 h-8" /> DarkHotel Security Auditor
          </h1>
          <div className="flex items-center gap-3">
            <span className="text-xs bg-blue-950/50 px-3 py-1 rounded-full text-blue-300 border border-blue-900/40">
              Pipeline v6.0
            </span>
            <span className="text-xs bg-purple-950/50 px-3 py-1 rounded-full text-purple-300 border border-purple-900/40">
              3 SWC Types
            </span>
          </div>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* LEFT COLUMN: Upload & Logs */}
          <div className="lg:col-span-4 space-y-4">
            {/* Upload Card */}
            <div className="bg-[#111827] p-6 rounded-xl border border-slate-800/60 shadow-xl">
              <h2 className="text-lg font-semibold mb-4 flex items-center gap-2 text-white">
                <Upload className="w-5 h-5 text-blue-400" /> Upload Contract
              </h2>

              <div className="border-2 border-dashed border-slate-700/60 rounded-lg p-8 text-center hover:border-blue-500/40 hover:bg-blue-950/10 transition-all cursor-pointer relative group">
                <input
                  type="file"
                  accept=".sol"
                  onChange={(e) => setFile(e.target.files?.[0] || null)}
                  className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                />
                <FileCode className="w-12 h-12 mx-auto text-slate-600 group-hover:text-blue-400 mb-2 transition-colors" />
                <p className="text-sm text-slate-400 group-hover:text-slate-200">
                  {file ? (
                    <span className="text-emerald-400 font-bold">{file.name}</span>
                  ) : (
                    "Select .sol file to scan"
                  )}
                </p>
              </div>

              <button
                onClick={handleAnalyze}
                disabled={loading || !file}
                className="mt-4 w-full bg-blue-600 hover:bg-blue-500 text-white py-3 rounded-lg font-bold transition-all disabled:opacity-40 flex items-center justify-center gap-2 shadow-lg shadow-blue-950/30"
              >
                {loading ? <Activity className="animate-spin" /> : <Search className="w-5 h-5" />}
                {loading ? "Analyzing..." : "Scan Vulnerabilities"}
              </button>
            </div>

            {/* Pipeline Steps */}
            <div className="bg-[#0d1117] p-4 rounded-xl border border-slate-800/60 shadow-inner">
              <div className="flex items-center justify-between text-slate-500 mb-3 border-b border-slate-800/40 pb-2">
                <div className="flex items-center gap-2 text-xs">
                  <Terminal className="w-3 h-3" /> Pipeline Status
                </div>
                {elapsedTime !== null && (
                  <span className="text-xs text-slate-500">{elapsedTime}s</span>
                )}
              </div>
              {steps.length === 0 ? (
                <span className="text-slate-700 italic text-xs">Waiting for input...</span>
              ) : (
                <div className="space-y-1">
                  {steps.map((step, i) => (
                    <div key={i} className="flex items-center gap-3 py-1.5">
                      {/* Step indicator */}
                      {step.status === "done" && (
                        <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                      )}
                      {step.status === "running" && (
                        <Activity className="w-4 h-4 text-blue-400 animate-spin shrink-0" />
                      )}
                      {step.status === "pending" && (
                        <div className="w-4 h-4 rounded-full border border-slate-700 shrink-0" />
                      )}
                      {step.status === "error" && (
                        <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                      )}
                      {/* Step label */}
                      <span className={`text-xs ${
                        step.status === "done" ? "text-emerald-300/80" :
                        step.status === "running" ? "text-blue-300 font-medium" :
                        step.status === "error" ? "text-red-400" :
                        "text-slate-600"
                      }`}>
                        {step.label}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* File Summary (when result exists) */}
            {result?.summary && (
              <div className="bg-[#111827] p-4 rounded-xl border border-slate-800/60 text-xs space-y-2">
                <h3 className="text-slate-300 font-semibold uppercase tracking-wider mb-2 text-[11px]">
                  Contract Info
                </h3>
                {[
                  ["File", result.filename],
                  ["Solidity", result.summary.solidity_version],
                  ["Lines", result.summary.total_lines],
                  ["Functions", result.summary.total_functions],
                  ["Model", result.llm_analysis?.model],
                ].map(([label, value]) => (
                  <div key={label} className="flex justify-between">
                    <span className="text-slate-500">{label}</span>
                    <span className="text-slate-200 font-medium">{value}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* RIGHT COLUMN: Results */}
          <div className="lg:col-span-8 space-y-4">
            {/* Error Banner */}
            {error && (
              <div className="rounded-xl border border-red-700/40 bg-red-950/30 p-5 flex items-start gap-3">
                <AlertTriangle className="w-6 h-6 text-red-400 shrink-0 mt-0.5" />
                <div>
                  <h3 className="text-red-400 font-bold text-sm">Analysis Failed</h3>
                  <p className="text-red-200/80 text-sm mt-1">{error}</p>
                </div>
              </div>
            )}

            {result ? (
              <>
                {/* === VERDICT BANNER === */}
                <div
                  className={`rounded-xl border p-6 flex items-center justify-between ${
                    isSafe
                      ? "bg-emerald-950/30 border-emerald-700/40"
                      : "bg-red-950/30 border-red-700/40"
                  }`}
                >
                  <div className="flex items-center gap-4">
                    {isSafe ? (
                      <ShieldCheck className="w-14 h-14 text-emerald-400" />
                    ) : (
                      <ShieldAlert className="w-14 h-14 text-red-400" />
                    )}
                    <div>
                      <h2
                        className={`text-3xl font-black tracking-wide ${
                          isSafe ? "text-emerald-400" : "text-red-400"
                        }`}
                      >
                        {verdict}
                      </h2>
                      <p className="text-sm text-slate-400 mt-1">
                        Confidence: <span className="text-slate-300">{confidence}</span>
                        {primary && (
                          <span className="ml-3 text-red-300/80">
                            Primary: {primary.type} ({primary.swc_id})
                          </span>
                        )}
                      </p>
                    </div>
                  </div>
                  <div className="flex flex-col gap-2 items-end">
                    <span className="text-xs bg-blue-950/60 text-blue-300 px-3 py-1 rounded-full border border-blue-900/30">
                      {result.llm_analysis?.model}
                    </span>
                    <span className="text-xs bg-purple-950/60 text-purple-300 px-3 py-1 rounded-full border border-purple-900/30">
                      RAG: {result.rag_findings?.top_k_ranked || 0} cases
                    </span>
                  </div>
                </div>

                {/* === PRIMARY VULNERABILITY === */}
                {primary && (
                  <div className="bg-[#111827] rounded-xl border border-red-800/40 shadow-xl overflow-hidden">
                    <div className="bg-red-950/40 px-5 py-3 border-b border-red-800/30 flex items-center justify-between">
                      <h3 className="font-bold text-red-400 flex items-center gap-2 uppercase text-sm tracking-wider">
                        <Crosshair className="w-4 h-4" /> Primary Vulnerability
                      </h3>
                      <div className="flex gap-2">
                        <span className={`px-2.5 py-0.5 rounded text-xs font-bold ${severityColor(primary.severity)}`}>
                          {primary.severity}
                        </span>
                        <span className="px-2.5 py-0.5 rounded text-xs bg-slate-700/80 text-slate-200 font-mono">
                          {primary.swc_id}
                        </span>
                      </div>
                    </div>
                    <div className="p-5 space-y-4">
                      <div>
                        <h4 className="text-lg font-bold text-white">{primary.type}</h4>
                        <p className="text-xs text-slate-500 mt-1 font-mono">
                          {primary.location}
                        </p>
                      </div>
                      <p className="text-sm text-slate-300 leading-relaxed">
                        {primary.description}
                      </p>
                      {primary.exploit_scenario && (
                        <div className="bg-red-950/20 p-4 rounded-lg border border-red-900/20">
                          <h5 className="text-xs font-bold text-red-400 uppercase mb-2 tracking-wider">
                            Exploit Scenario
                          </h5>
                          <p className="text-sm text-red-100/70 leading-relaxed">
                            {primary.exploit_scenario}
                          </p>
                        </div>
                      )}
                      {primary.recommendation && (
                        <div className="bg-emerald-950/20 p-4 rounded-lg border border-emerald-900/20">
                          <h5 className="text-xs font-bold text-emerald-400 uppercase mb-2 tracking-wider">
                            Recommendation
                          </h5>
                          <p className="text-sm text-emerald-100/70 leading-relaxed">
                            {primary.recommendation}
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* === SECONDARY WARNINGS === */}
                {secondaries.length > 0 && (
                  <div className="bg-[#111827] rounded-xl border border-amber-800/30 shadow-xl overflow-hidden">
                    <div className="bg-amber-950/20 px-5 py-3 border-b border-amber-800/20">
                      <h3 className="font-bold text-amber-400 flex items-center gap-2 uppercase text-sm tracking-wider">
                        <AlertTriangle className="w-4 h-4" /> Secondary Warnings ({secondaries.length})
                      </h3>
                    </div>
                    <div className="divide-y divide-slate-800/50">
                      {secondaries.map((sec: any, idx: number) => (
                        <div key={idx} className="p-4 flex items-start gap-3">
                          <span className={`px-2 py-0.5 rounded text-xs font-bold mt-0.5 shrink-0 ${severityColor(sec.severity)}`}>
                            {sec.severity}
                          </span>
                          <div className="min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-sm font-semibold text-white">{sec.type}</span>
                              <span className="text-xs text-slate-400 bg-slate-800/60 px-2 py-0.5 rounded font-mono">
                                {sec.swc_id}
                              </span>
                            </div>
                            <p className="text-xs text-slate-500 mt-0.5 font-mono">{sec.location}</p>
                            <p className="text-xs text-slate-400 mt-1 leading-relaxed">{sec.description}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* === SAFE MESSAGE === */}
                {isSafe && !primary && (
                  <div className="bg-emerald-950/15 rounded-xl border border-emerald-800/25 p-6 text-center">
                    <CheckCircle className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
                    <p className="text-emerald-300 font-semibold">
                      No vulnerabilities detected in the 3 target categories
                    </p>
                    <p className="text-xs text-slate-500 mt-2">
                      Checked: Reentrancy (SWC-107) | Integer Overflow (SWC-101) | Unchecked Return Value (SWC-104)
                    </p>
                  </div>
                )}

                {/* === COLLAPSIBLE: Slither === */}
                {result.slither_analysis?.total_warnings > 0 && (
                  <div className="bg-[#111827] rounded-xl border border-slate-800/60 overflow-hidden">
                    <button
                      onClick={() => setShowSlither(!showSlither)}
                      className="w-full px-5 py-3 flex items-center justify-between hover:bg-slate-800/30 transition-colors"
                    >
                      <h3 className="font-bold text-orange-400 flex items-center gap-2 text-sm uppercase tracking-wider">
                        <AlertTriangle className="w-4 h-4" /> Slither Static Analysis
                        <span className="text-xs bg-orange-950/50 text-orange-300 px-2 py-0.5 rounded-full font-normal ml-1">
                          {result.slither_analysis.total_warnings}
                        </span>
                      </h3>
                      {showSlither ? (
                        <ChevronUp className="w-4 h-4 text-slate-500" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-slate-500" />
                      )}
                    </button>
                    {showSlither && (
                      <div className="px-5 pb-4 space-y-2">
                        {result.slither_analysis.warnings.map((warning: string, idx: number) => (
                          <div
                            key={idx}
                            className={`text-xs p-2.5 rounded ${slitherWarningStyle(warning)}`}
                          >
                            {warning}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* === COLLAPSIBLE: RAG Findings === */}
                {result.rag_findings?.vuln_type && (
                  <div className="bg-[#111827] rounded-xl border border-slate-800/60 overflow-hidden">
                    <button
                      onClick={() => setShowRag(!showRag)}
                      className="w-full px-5 py-3 flex items-center justify-between hover:bg-slate-800/30 transition-colors"
                    >
                      <h3 className="font-bold text-violet-400 flex items-center gap-2 text-sm uppercase tracking-wider">
                        <Database className="w-4 h-4" /> RAG Knowledge Base
                        <span className="text-xs bg-violet-950/50 text-violet-300 px-2 py-0.5 rounded-full font-normal ml-1">
                          {result.rag_findings?.version}
                        </span>
                      </h3>
                      {showRag ? (
                        <ChevronUp className="w-4 h-4 text-slate-500" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-slate-500" />
                      )}
                    </button>
                    {showRag && (
                      <div className="px-5 pb-4 space-y-3">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2.5 py-0.5 rounded text-xs font-medium ${
                              result.rag_findings?.found
                                ? "bg-red-900/40 text-red-300"
                                : "bg-emerald-900/40 text-emerald-300"
                            }`}
                          >
                            {result.rag_findings.vuln_type}
                          </span>
                          <span className="text-xs text-slate-500">
                            {result.rag_findings.total_candidates} candidates, {result.rag_findings.top_k_ranked} ranked
                          </span>
                        </div>
                        {result.rag_findings.crag_action && (
                          <div className="flex items-center gap-2">
                            <span className={`px-2 py-0.5 rounded text-xs ${
                              result.rag_findings.crag_action === "CORRECT"
                                ? "bg-emerald-900/40 text-emerald-300"
                                : result.rag_findings.crag_action === "AMBIGUOUS"
                                ? "bg-amber-900/40 text-amber-300"
                                : "bg-slate-800/40 text-slate-400"
                            }`}>
                              CRAG: {result.rag_findings.crag_action}
                            </span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {/* === COLLAPSIBLE: AI Reasoning === */}
                {(reasoning || result.ai_analysis) && (
                  <div className="bg-[#111827] rounded-xl border border-slate-800/60 overflow-hidden">
                    <button
                      onClick={() => setShowReasoning(!showReasoning)}
                      className="w-full px-5 py-3 flex items-center justify-between hover:bg-slate-800/30 transition-colors"
                    >
                      <h3 className="font-bold text-cyan-400 flex items-center gap-2 text-sm uppercase tracking-wider">
                        <Info className="w-4 h-4" /> AI Chain-of-Thought Reasoning
                      </h3>
                      {showReasoning ? (
                        <ChevronUp className="w-4 h-4 text-slate-500" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-slate-500" />
                      )}
                    </button>
                    {showReasoning && (
                      <div className="px-5 pb-4">
                        <div className="bg-[#0d1117] p-5 rounded-lg border border-slate-800/40 text-slate-300 text-sm leading-relaxed prose prose-invert prose-sm max-w-none">
                          {reasoning ? (
                            <ReactMarkdown>{reasoning}</ReactMarkdown>
                          ) : (
                            <ReactMarkdown>{result.ai_analysis}</ReactMarkdown>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-slate-600 border-2 border-dashed border-slate-800/40 rounded-xl bg-[#111827]/50 min-h-[500px]">
                <ShieldAlert className="w-20 h-20 mb-4 opacity-10" />
                <p className="text-slate-500">Upload a .sol file and click Scan to begin</p>
                <p className="text-xs text-slate-700 mt-2">
                  Detects: Reentrancy | Integer Overflow | Unchecked Return Value
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
