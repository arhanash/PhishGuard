import React from 'react';
import { 
  BookOpen, ShieldCheck, AlertTriangle, Cpu, Terminal, 
  Lock, Globe, Mail, CheckCircle2, ChevronRight, Layers, FileCode 
} from 'lucide-react';

export default function SecurityGuide() {
  return (
    <div className="space-y-8 max-w-5xl mx-auto animate-in fade-in duration-300">
      {/* Title */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/30 text-indigo-300 text-xs font-mono">
          <BookOpen className="w-3.5 h-3.5" />
          <span>B.Tech Cybersecurity Academic Reference & Playbook</span>
        </div>
        <h2 className="text-3xl font-extrabold text-white tracking-tight">
          PhishGuard Defense Architecture & Security Playbook
        </h2>
        <p className="text-sm text-slate-400 max-w-2xl mx-auto">
          Theoretical foundations, machine learning methodology, threat actor vectors, and tactical incident mitigation guidelines.
        </p>
      </div>

      {/* Grid: 3 Foundation Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 backdrop-blur-xl space-y-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-950/60 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Globe className="w-5 h-5" />
          </div>
          <h3 className="text-base font-bold text-white">URL Phishing Analysis</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Extracts 22 lexical and structural dimensions including Shannon entropy, raw IP detection, homoglyphs (punycode xn--), suspicious TLD statistics, and subdomain depth.
          </p>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 backdrop-blur-xl space-y-3">
          <div className="w-10 h-10 rounded-xl bg-purple-950/60 border border-purple-500/30 flex items-center justify-center text-purple-400">
            <Mail className="w-5 h-5" />
          </div>
          <h3 className="text-base font-bold text-white">Email & BEC Semantics</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Scans for sender display name spoofing, emotional coercion cues (fear/urgency), high-risk attachments (.iso, .exe, .vbs), and extracts nested URLs for recursive inspection.
          </p>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 backdrop-blur-xl space-y-3">
          <div className="w-10 h-10 rounded-xl bg-indigo-950/60 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
            <Cpu className="w-5 h-5" />
          </div>
          <h3 className="text-base font-bold text-white">Hybrid Ensemble ML</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Unites Random Forest decision tree ensembles with TF-IDF n-gram vectorization and deterministic heuristic policies to prevent false negatives and provide explainable threat scores.
          </p>
        </div>
      </div>

      {/* MITRE ATT&CK Mapping Table */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 backdrop-blur-xl space-y-4">
        <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <h3 className="text-base font-bold text-white tracking-wide">
            MITRE ATT&CK Enterprise Matrix Alignment
          </h3>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                <th className="py-2.5 px-3">Technique ID</th>
                <th className="py-2.5 px-3">Name</th>
                <th className="py-2.5 px-3">Tactic</th>
                <th className="py-2.5 px-3">Detection Logic in PhishGuard</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr>
                <td className="py-2.5 px-3 text-cyan-300 font-bold">T1566.002</td>
                <td className="py-2.5 px-3">Spearphishing Link</td>
                <td className="py-2.5 px-3 text-slate-400">Initial Access</td>
                <td className="py-2.5 px-3">URL token parser, punycode check, shortener expander, lexical ML.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-3 text-cyan-300 font-bold">T1566.001</td>
                <td className="py-2.5 px-3">Spearphishing Attachment</td>
                <td className="py-2.5 px-3 text-slate-400">Initial Access</td>
                <td className="py-2.5 px-3">Header and body regex scanner for executable and archive containers (.iso, .scr, .exe).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-3 text-cyan-300 font-bold">T1598.003</td>
                <td className="py-2.5 px-3">Phishing for Information: Credentials</td>
                <td className="py-2.5 px-3 text-slate-400">Reconnaissance / Credential Access</td>
                <td className="py-2.5 px-3">Target keyword clustering (login, verify, banking, password, ssn, pin).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-3 text-cyan-300 font-bold">T1568.002</td>
                <td className="py-2.5 px-3">Domain Generation Algorithms (DGA)</td>
                <td className="py-2.5 px-3 text-slate-400">Command & Control</td>
                <td className="py-2.5 px-3">Shannon Entropy computation (H &gt; 3.8 bits flags machine-generated domains).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-3 text-cyan-300 font-bold">T1583.001</td>
                <td className="py-2.5 px-3">Acquire Domains: High-Abuse TLDs</td>
                <td className="py-2.5 px-3 text-slate-400">Resource Development</td>
                <td className="py-2.5 px-3">Blacklist telemetry matching high-abuse TLDs (.xyz, .top, .buzz, .tk, etc.).</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Incident Response Playbook */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 backdrop-blur-xl space-y-4">
        <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <h3 className="text-base font-bold text-white tracking-wide">
            Enterprise Phishing Incident Response Playbook
          </h3>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
            <span className="text-cyan-400 font-mono font-bold">PHASE 1: IDENTIFICATION & TRIAGE</span>
            <p className="text-slate-300 leading-relaxed">
              When an alert fires with Risk Score &gt; 70%, immediately isolate the affected workstation. Extract the RFC 822 raw headers, target URL, and submit to PhishGuard for forensic indicator analysis.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
            <span className="text-cyan-400 font-mono font-bold">PHASE 2: CONTAINMENT</span>
            <p className="text-slate-300 leading-relaxed">
              Null-route the malicious domain in internal DNS sinkholes. Block inbound mail from the spoofed sender address or envelope domain across the email gateway (SEG).
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
            <span className="text-cyan-400 font-mono font-bold">PHASE 3: ERADICATION</span>
            <p className="text-slate-300 leading-relaxed">
              Purge matching phishing emails from all user mailboxes across Microsoft 365 or Google Workspace. Force password resets and revoke active OAuth tokens for any user who clicked.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
            <span className="text-cyan-400 font-mono font-bold">PHASE 4: LESSONS LEARNED</span>
            <p className="text-slate-300 leading-relaxed">
              Export PhishGuard's forensic PDF report into the SOC ticketing system. Update machine learning training datasets with the new IOCs to harden future detection sensitivity.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

