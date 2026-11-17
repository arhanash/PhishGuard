import React, { useState, useEffect } from 'react';
import { ShieldCheck, Cpu, Terminal, Radio } from 'lucide-react';

const STEPS = [
  'Parsing Target Structure & Normalizing Input Vector...',
  'Computing Shannon Entropy & Lexical Distribution Metrics...',
  'Analyzing Domain Infrastructure & Homoglyph Deception...',
  'Executing Scikit-Learn Machine Learning Classifier...',
  'Evaluating Heuristic Threat Matrix & MITRE ATT&CK Mapping...',
  'Synthesizing Forensic Risk Report & Mitigations...'
];

export default function CyberScannerAnimation({ scanType = 'URL' }) {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentStepIndex((prev) => (prev < STEPS.length - 1 ? prev + 1 : prev));
    }, 450);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="relative overflow-hidden rounded-2xl border border-indigo-500/30 bg-slate-950/90 p-8 cyber-grid cyber-glow-purple shadow-2xl">
      {/* Background radial gradient glow */}
      <div className="absolute inset-0 bg-gradient-to-b from-indigo-950/20 via-transparent to-purple-950/30 pointer-events-none" />

      <div className="relative z-10 flex flex-col items-center text-center">
        {/* Animated Cyber Radar */}
        <div className="relative w-44 h-44 mb-6 flex items-center justify-center">
          {/* Outer ring */}
          <div className="absolute inset-0 rounded-full border-2 border-indigo-500/30 animate-pulse-slow"></div>
          {/* Middle ring */}
          <div className="absolute inset-4 rounded-full border border-cyan-500/30 border-dashed"></div>
          {/* Inner ring */}
          <div className="absolute inset-10 rounded-full border border-purple-500/40"></div>
          {/* Center core */}
          <div className="w-12 h-12 rounded-full bg-gradient-to-tr from-indigo-600 to-cyan-500 flex items-center justify-center shadow-lg shadow-cyan-500/50">
            <Radio className="w-6 h-6 text-white animate-spin" style={{ animationDuration: '6s' }} />
          </div>

          {/* Radar Sweep Needle */}
          <div className="absolute inset-0 rounded-full animate-radar origin-center pointer-events-none">
            <div className="w-1/2 h-1/2 bg-gradient-to-br from-cyan-400/30 to-transparent rounded-tl-full"></div>
          </div>

          {/* Crosshairs */}
          <div className="absolute inset-x-0 top-1/2 h-px bg-cyan-500/20"></div>
          <div className="absolute inset-y-0 left-1/2 w-px bg-cyan-500/20"></div>
        </div>

        {/* Status text */}
        <div className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-indigo-500/10 border border-indigo-500/30 mb-3">
          <Cpu className="w-4 h-4 text-cyan-400 animate-pulse" />
          <span className="text-xs font-mono font-semibold tracking-wider text-cyan-300 uppercase">
            AI Threat Engine Active • {scanType} Telemetry
          </span>
        </div>

        <h3 className="text-xl font-bold text-white tracking-wide mb-2">
          Deep Threat Inspection In Progress
        </h3>

        {/* Dynamic Telemetry Log */}
        <div className="w-full max-w-lg mt-4 bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 font-mono text-left text-xs shadow-inner">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800/80 mb-2.5 text-slate-400 text-[11px]">
            <span className="flex items-center space-x-1.5">
              <Terminal className="w-3.5 h-3.5 text-indigo-400" />
              <span>FORENSIC_KERNEL_LOG</span>
            </span>
            <span className="text-cyan-400 font-semibold animate-pulse">LIVE_INFERENCE</span>
          </div>

          <div className="space-y-1.5">
            {STEPS.map((step, idx) => {
              const isPast = idx < currentStepIndex;
              const isCurrent = idx === currentStepIndex;
              return (
                <div
                  key={idx}
                  className={`flex items-center space-x-2 transition-opacity duration-200 ${
                    isPast
                      ? 'text-emerald-400 opacity-90'
                      : isCurrent
                      ? 'text-cyan-300 font-semibold'
                      : 'text-slate-600 opacity-40'
                  }`}
                >
                  <span className="text-[10px]">
                    {isPast ? '[DONE]' : isCurrent ? '[EXEC]' : '[WAIT]'}
                  </span>
                  <span className="truncate">{step}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

