import React, { useState } from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, Download, 
  ExternalLink, FileText, CheckCircle2, Lock, Unlock, 
  Cpu, Activity, RefreshCw, Hash, Server, Layers, AlertOctagon
} from 'lucide-react';
import jsPDF from 'jspdf';
import { api } from '../services/api';

export default function ThreatResults({ result, onReset }) {
  const [downloading, setDownloading] = useState(false);

  if (!result) return null;

  const {
    id,
    scan_type,
    target,
    risk_score,
    classification,
    threat_summary,
    threat_indicators = [],
    detailed_analysis = {},
    security_recommendations = [],
    timestamp
  } = result;

  const isSafe = classification === 'Safe';
  const isSuspicious = classification === 'Suspicious';
  const isMalicious = classification === 'Malicious';

  // Badge & Color scheme mapping
  const badgeConfig = isSafe
    ? {
        border: 'border-emerald-500/40',
        bg: 'bg-emerald-950/40',
        text: 'text-emerald-400',
        glow: 'cyber-glow-green',
        icon: ShieldCheck,
        bar: 'bg-emerald-500',
        pill: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50'
      }
    : isSuspicious
    ? {
        border: 'border-amber-500/40',
        bg: 'bg-amber-950/40',
        text: 'text-amber-400',
        glow: 'border-amber-500/30 shadow-amber-500/20',
        icon: AlertTriangle,
        bar: 'bg-amber-500',
        pill: 'bg-amber-500/20 text-amber-300 border-amber-500/50'
      }
    : {
        border: 'border-rose-500/50',
        bg: 'bg-rose-950/40',
        text: 'text-rose-400',
        glow: 'cyber-glow-red',
        icon: ShieldAlert,
        bar: 'bg-rose-500',
        pill: 'bg-rose-500/20 text-rose-300 border-rose-500/50'
      };

  const StatusIcon = badgeConfig.icon;

  const handleDownloadTxt = async () => {
    try {
      if (id) {
        await api.downloadReport(id, 'txt');
      } else {
        alert('Scan ID missing from active session.');
      }
    } catch (e) {
      alert('Error downloading report: ' + e.message);
    }
  };

  const handleDownloadJson = async () => {
    try {
      if (id) {
        await api.downloadReport(id, 'json');
      } else {
        // Fallback local download
        const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `phishguard_scan_${Date.now()}.json`;
        a.click();
      }
    } catch (e) {
      alert('Error downloading JSON: ' + e.message);
    }
  };

  const handleGeneratePdf = () => {
    setDownloading(true);
    try {
      const doc = new jsPDF();
      
      // Header
      doc.setFillColor(10, 14, 23);
      doc.rect(0, 0, 210, 40, 'F');
      
      doc.setTextColor(56, 189, 248);
      doc.setFontSize(20);
      doc.setFont('helvetica', 'bold');
      doc.text('PHISHGUARD CYBERSECURITY INTELLIGENCE', 14, 18);
      
      doc.setFontSize(10);
      doc.setTextColor(203, 213, 225);
      doc.text('AI-Powered Phishing Threat Forensic Report', 14, 26);
      doc.text(`Report ID: PG-SEC-${id || 'SESSION'}   |   Timestamp: ${new Date().toLocaleString()}`, 14, 33);
      
      // Target Box
      doc.setFillColor(241, 245, 249);
      doc.rect(14, 46, 182, 22, 'F');
      doc.setTextColor(30, 41, 59);
      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      doc.text(`Target Type: ${scan_type?.toUpperCase()} SCAN`, 18, 53);
      doc.setFont('helvetica', 'normal');
      doc.text(`Target Entity: ${target.substring(0, 75)}`, 18, 62);
      
      // Classification Box
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(12);
      let riskR = isMalicious ? 225 : isSuspicious ? 217 : 22;
      let riskG = isMalicious ? 29 : isSuspicious ? 119 : 163;
      let riskB = isMalicious ? 72 : isSuspicious ? 6 : 74;
      doc.setTextColor(riskR, riskG, riskB);
      doc.text(`THREAT CLASSIFICATION: ${classification.toUpperCase()}  |  RISK SCORE: ${risk_score} / 100`, 14, 76);
      
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9.5);
      doc.setTextColor(51, 65, 85);
      const splitSummary = doc.splitTextToSize(`Verdict: ${threat_summary}`, 180);
      doc.text(splitSummary, 14, 84);
      
      // Indicators Section
      let currentY = 100;
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(11);
      doc.setTextColor(15, 23, 42);
      doc.text(`DETECTED THREAT INDICATORS (${threat_indicators.length})`, 14, currentY);
      currentY += 6;
      doc.setDrawColor(203, 213, 225);
      doc.line(14, currentY, 196, currentY);
      currentY += 6;
      
      doc.setFontSize(9);
      if (threat_indicators.length === 0) {
        doc.setFont('helvetica', 'italic');
        doc.text('No malicious indicators triggered. Nominal benign baseline.', 14, currentY);
        currentY += 8;
      } else {
        threat_indicators.forEach((ind, idx) => {
          if (currentY > 260) {
            doc.addPage();
            currentY = 20;
          }
          doc.setFont('helvetica', 'bold');
          doc.setTextColor(isMalicious ? 185 : 51, 28, 28);
          doc.text(`${idx + 1}. [${ind.severity}] ${ind.name} (MITRE: ${ind.mitre_ref || 'T1566'})`, 14, currentY);
          currentY += 5;
          doc.setFont('helvetica', 'normal');
          doc.setTextColor(71, 85, 105);
          const descLines = doc.splitTextToSize(ind.description, 175);
          doc.text(descLines, 18, currentY);
          currentY += (descLines.length * 4.5) + 3;
        });
      }
      
      // Recommendations Section
      if (currentY > 240) {
        doc.addPage();
        currentY = 20;
      }
      currentY += 4;
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(11);
      doc.setTextColor(15, 23, 42);
      doc.text('FORENSIC MITIGATION & PLAYBOOK ACTIONS', 14, currentY);
      currentY += 6;
      doc.line(14, currentY, 196, currentY);
      currentY += 6;
      
      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(51, 65, 85);
      security_recommendations.forEach((rec, idx) => {
        if (currentY > 275) {
          doc.addPage();
          currentY = 20;
        }
        const recLines = doc.splitTextToSize(`[${idx + 1}] ${rec}`, 180);
        doc.text(recLines, 14, currentY);
        currentY += (recLines.length * 4.5) + 2;
      });
      
      // Footer
      doc.setFontSize(8);
      doc.setTextColor(148, 163, 184);
      doc.text('PhishGuard AI Engine • B.Tech Cybersecurity Capstone Defense Architecture', 14, 288);
      
      doc.save(`PhishGuard_Report_${id || 'Result'}.pdf`);
    } catch (e) {
      console.error('PDF generation error:', e);
      alert('PDF generation failed: ' + e.message);
    } finally {
      setDownloading(false);
    }
  };

  const domainMeta = detailed_analysis.domain_metadata || {};
  const lexicalFeats = detailed_analysis.lexical_features || {};
  const emailMeta = detailed_analysis.metadata || {};
  const dnsInfo = detailed_analysis.dns_info || {};

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Top Threat Classification Banner */}
      <div className={`relative overflow-hidden rounded-2xl border ${badgeConfig.border} ${badgeConfig.bg} backdrop-blur-xl p-6 sm:p-8 shadow-2xl`}>
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          {/* Left: Target and Verdict */}
          <div className="space-y-3 flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className={`inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold tracking-wider uppercase border ${badgeConfig.pill}`}>
                <StatusIcon className="w-4 h-4" />
                <span>{classification} THREAT LEVEL</span>
              </span>
              <span className="text-xs font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-900/60 border border-slate-800">
                Type: {scan_type?.toUpperCase()}
              </span>
              {id && (
                <span className="text-xs font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-900/60 border border-slate-800">
                  ID: #{id}
                </span>
              )}
            </div>

            <div className="truncate">
              <span className="text-xs font-mono text-slate-400 block mb-0.5">Scanned Target:</span>
              <p className="text-sm sm:text-base font-mono text-cyan-200 truncate bg-slate-950/60 px-3 py-1.5 rounded-lg border border-slate-800/80">
                {target}
              </p>
            </div>

            <p className="text-sm text-slate-300 leading-relaxed font-sans">
              {threat_summary}
            </p>
          </div>

          {/* Right: Circular / Radial Risk Score Gauge */}
          <div className="flex flex-col items-center justify-center bg-slate-950/80 p-5 rounded-2xl border border-slate-800/80 min-w-[210px] shadow-lg">
            <div className="relative w-32 h-32 flex items-center justify-center">
              {/* SVG circular meter */}
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                <circle
                  cx="50"
                  cy="50"
                  r="40"
                  className="stroke-slate-800"
                  strokeWidth="8"
                  fill="transparent"
                />
                <circle
                  cx="50"
                  cy="50"
                  r="40"
                  className={`${isSafe ? 'stroke-emerald-500' : isSuspicious ? 'stroke-amber-500' : 'stroke-rose-500'} transition-all duration-1000 ease-out`}
                  strokeWidth="8"
                  strokeDasharray="251.2"
                  strokeDashoffset={251.2 - (251.2 * risk_score) / 100}
                  strokeLinecap="round"
                  fill="transparent"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className="text-3xl font-black font-mono tracking-tight text-white">
                  {risk_score}%
                </span>
                <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400">
                  Risk Score
                </span>
              </div>
            </div>

            {/* Sub-metrics */}
            <div className="w-full grid grid-cols-2 gap-2 mt-3 pt-3 border-t border-slate-800/80 text-center text-[11px] font-mono">
              <div>
                <span className="text-slate-400 block">ML Confidence</span>
                <span className="font-bold text-cyan-300">{detailed_analysis.ml_phishing_probability || 0}%</span>
              </div>
              <div>
                <span className="text-slate-400 block">Heuristics</span>
                <span className="font-bold text-purple-300">{detailed_analysis.heuristic_score || 0}%</span>
              </div>
            </div>
          </div>
        </div>

        {/* Action Controls Bar */}
        <div className="mt-6 pt-5 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={handleGeneratePdf}
              disabled={downloading}
              className="inline-flex items-center space-x-2 px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold tracking-wide transition-all shadow-md shadow-indigo-600/30"
            >
              <Download className="w-3.5 h-3.5" />
              <span>{downloading ? 'Compiling PDF...' : 'Download PDF Report'}</span>
            </button>
            <button
              onClick={handleDownloadTxt}
              className="inline-flex items-center space-x-2 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 text-xs font-medium transition-all"
            >
              <FileText className="w-3.5 h-3.5 text-slate-400" />
              <span>Forensic TXT</span>
            </button>
            <button
              onClick={handleDownloadJson}
              className="inline-flex items-center space-x-2 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 text-xs font-medium transition-all"
            >
              <Hash className="w-3.5 h-3.5 text-slate-400" />
              <span>Raw JSON</span>
            </button>
          </div>

          <button
            onClick={onReset}
            className="inline-flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-slate-900/60 hover:bg-slate-800 text-slate-300 text-xs font-medium transition-all border border-slate-800"
          >
            <RefreshCw className="w-3.5 h-3.5 text-slate-400" />
            <span>Scan Another</span>
          </button>
        </div>
      </div>

      {/* Grid: Forensic Breakdown & Technical Inspection */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Detected Threat Indicators (2/3 width) */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Layers className="w-5 h-5 text-indigo-400" />
              <h4 className="text-base font-bold text-white tracking-wide">
                Detected Forensic Threat Indicators ({threat_indicators.length})
              </h4>
            </div>
            <span className="text-xs font-mono text-slate-400">
              MITRE ATT&CK Mapping
            </span>
          </div>

          {threat_indicators.length === 0 ? (
            <div className="p-6 rounded-xl border border-emerald-500/20 bg-emerald-950/20 text-center space-y-2">
              <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
              <p className="text-sm font-semibold text-emerald-300">
                Zero Malicious Threat Signatures Triggered
              </p>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                The target has successfully passed lexical, entropy, homoglyph, and NLP machine learning heuristics tests.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {threat_indicators.map((ind, i) => {
                const isCrit = ind.severity === 'Critical';
                const isHigh = ind.severity === 'High';
                const isMed = ind.severity === 'Medium';
                const sevColor = isCrit
                  ? 'border-rose-500/40 bg-rose-950/30 text-rose-300'
                  : isHigh
                  ? 'border-orange-500/40 bg-orange-950/30 text-orange-300'
                  : isMed
                  ? 'border-amber-500/40 bg-amber-950/30 text-amber-300'
                  : 'border-blue-500/40 bg-blue-950/30 text-blue-300';

                return (
                  <div
                    key={i}
                    className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 hover:bg-slate-900/90 transition-all space-y-2"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${sevColor}`}>
                          {ind.severity}
                        </span>
                        <span className="text-sm font-semibold text-slate-100">
                          {ind.name}
                        </span>
                      </div>
                      <div className="flex items-center space-x-2 text-xs font-mono">
                        {ind.mitre_ref && (
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700 text-[10px]">
                            {ind.mitre_ref}
                          </span>
                        )}
                        <span className="text-rose-400 font-bold">
                          +{ind.score_impact} pts
                        </span>
                      </div>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      {ind.description}
                    </p>
                    <div className="text-[11px] font-mono text-slate-500">
                      Category: <span className="text-slate-400">{ind.category}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column: Technical Inspection Metadata & Security Playbook */}
        <div className="space-y-6">
          {/* Metadata Inspector Card */}
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/70 space-y-4">
            <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
              <Server className="w-4 h-4 text-cyan-400" />
              <h5 className="text-xs font-mono font-bold tracking-wider uppercase text-slate-300">
                Technical Forensic Telemetry
              </h5>
            </div>

            {scan_type === 'url' ? (
              <div className="space-y-2.5 text-xs font-mono">
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Hostname:</span>
                  <span className="text-cyan-300 font-semibold truncate max-w-[160px]">
                    {domainMeta.hostname || 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Top-Level Domain:</span>
                  <span className={`font-semibold ${domainMeta.suspicious_tld ? 'text-rose-400' : 'text-slate-200'}`}>
                    .{domainMeta.tld || 'N/A'} {domainMeta.suspicious_tld ? '(Abuse)' : ''}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Protocol:</span>
                  <span className="flex items-center space-x-1">
                    {domainMeta.scheme === 'https' ? (
                      <span className="text-emerald-400 flex items-center space-x-1">
                        <Lock className="w-3 h-3" />
                        <span>HTTPS</span>
                      </span>
                    ) : (
                      <span className="text-amber-400 flex items-center space-x-1">
                        <Unlock className="w-3 h-3" />
                        <span>HTTP</span>
                      </span>
                    )}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">DNS Resolution:</span>
                  <span className={`font-semibold ${dnsInfo.status?.includes('NXDOMAIN') ? 'text-rose-400' : 'text-slate-200'}`}>
                    {dnsInfo.status || 'Lookup Done'}
                  </span>
                </div>
                {dnsInfo.resolved_ip && (
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">Resolved IP:</span>
                    <span className="text-slate-200">{dnsInfo.resolved_ip}</span>
                  </div>
                )}
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Shannon Entropy:</span>
                  <span className="text-purple-300">{domainMeta.hostname_entropy || 0} bits</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Subdomain Depth:</span>
                  <span className="text-slate-200">{domainMeta.subdomain_depth || 0}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-400">IP Hostname:</span>
                  <span className={domainMeta.is_ip ? 'text-rose-400 font-bold' : 'text-slate-200'}>
                    {domainMeta.is_ip ? 'TRUE (Direct IP)' : 'FALSE (DNS Name)'}
                  </span>
                </div>
              </div>
            ) : (
              <div className="space-y-2.5 text-xs font-mono">
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Sender Spoofing:</span>
                  <span className={emailMeta.impersonation_flag ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
                    {emailMeta.impersonation_flag ? `YES (${emailMeta.impersonated_brand})` : 'NO'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Urgency Triggers:</span>
                  <span className="text-amber-300">{emailMeta.matched_urgency?.length || 0} detected</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Credential Solicitations:</span>
                  <span className="text-rose-400 font-bold">{emailMeta.matched_credentials?.length || 0} detected</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Caps Ratio:</span>
                  <span className="text-slate-200">{(emailMeta.caps_ratio * 100).toFixed(1)}%</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-400">Embedded URLs:</span>
                  <span className="text-cyan-300 font-bold">{emailMeta.found_urls?.length || 0}</span>
                </div>
              </div>
            )}
          </div>

          {/* Security Recommendations Card */}
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/70 space-y-3">
            <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <h5 className="text-xs font-mono font-bold tracking-wider uppercase text-slate-300">
                Security Recommendations
              </h5>
            </div>
            <ul className="space-y-2 text-xs text-slate-300">
              {security_recommendations.map((rec, i) => (
                <li key={i} className="flex items-start space-x-2">
                  <span className="text-cyan-400 font-mono font-bold mt-0.5">•</span>
                  <span className="leading-relaxed">{rec}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}

