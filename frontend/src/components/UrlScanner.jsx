import React, { useState } from 'react';
import { Globe, Search, ArrowRight, Sparkles, Shield, AlertCircle, Clipboard, X } from 'lucide-react';
import { api } from '../services/api';
import { SAMPLE_CASES } from '../sampleData';
import CyberScannerAnimation from './CyberScannerAnimation';
import ThreatResults from './ThreatResults';

export default function UrlScanner({ onScanComplete }) {
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [scanResult, setScanResult] = useState(null);

  const handleScan = async (targetUrl = null) => {
    const finalUrl = (targetUrl || urlInput).trim();
    if (!finalUrl) {
      setError('Please provide a valid website URL or domain name to scan.');
      return;
    }

    setError(null);
    setLoading(true);
    setScanResult(null);

    try {
      // Small artificial pause (1.2s) so the high-tech cyber radar animation can execute smoothly
      const [res] = await Promise.all([
        api.scanUrl(finalUrl),
        new Promise((resolve) => setTimeout(resolve, 1400)),
      ]);
      setScanResult(res);
      if (onScanComplete) onScanComplete(res);
    } catch (err) {
      console.error(err);
      setError(err.message || 'An error occurred while inspecting the URL.');
    } finally {
      setLoading(false);
    }
  };

  const handleSelectSample = (sample) => {
    setUrlInput(sample.url);
    handleScan(sample.url);
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) setUrlInput(text);
    } catch (e) {
      // Clipboard access denied or unsupported
    }
  };

  return (
    <div className="space-y-8">
      {/* Hero Headline */}
      <div className="text-center max-w-3xl mx-auto space-y-3">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-gradient-to-r from-indigo-500/10 via-purple-500/10 to-cyan-500/10 border border-indigo-500/30 text-cyan-300 text-xs font-mono">
          <Sparkles className="w-3.5 h-3.5" />
          <span>Real-Time Lexical & Machine Learning Threat Engine</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          AI-Powered Phishing URL Detection
        </h1>
        <p className="text-sm sm:text-base text-slate-400">
          Analyze suspicious domains, homoglyph attacks, IP hostnames, URL shorteners, and obfuscated subdomains using Random Forest classification and deterministic heuristics.
        </p>
      </div>

      {/* Input Box Card */}
      <div className="max-w-4xl mx-auto bg-slate-900/80 border border-slate-800 rounded-2xl p-4 sm:p-6 backdrop-blur-xl cyber-glow-blue shadow-2xl space-y-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleScan();
          }}
          className="relative flex flex-col sm:flex-row items-stretch gap-2"
        >
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
              <Globe className="w-5 h-5 text-indigo-400" />
            </div>
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Enter or paste URL (e.g., https://secure-bank-login.xyz/auth)..."
              disabled={loading}
              className="w-full pl-11 pr-20 py-3.5 bg-slate-950/90 border border-slate-700/80 rounded-xl text-slate-100 placeholder-slate-500 text-sm focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all font-mono"
            />
            {/* Quick paste / clear buttons inside input */}
            <div className="absolute inset-y-0 right-0 pr-2 flex items-center space-x-1">
              {urlInput && !loading && (
                <button
                  type="button"
                  onClick={() => setUrlInput('')}
                  className="p-1.5 text-slate-400 hover:text-slate-200 rounded-md hover:bg-slate-800"
                  title="Clear input"
                >
                  <X className="w-4 h-4" />
                </button>
              )}
              <button
                type="button"
                onClick={handlePaste}
                className="p-1.5 text-slate-400 hover:text-cyan-400 rounded-md hover:bg-slate-800 hidden sm:block"
                title="Paste from clipboard"
              >
                <Clipboard className="w-4 h-4" />
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="flex items-center justify-center space-x-2 px-6 py-3.5 rounded-xl bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white font-semibold text-sm shadow-lg shadow-indigo-600/30 transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer whitespace-nowrap"
          >
            <Shield className="w-4 h-4 text-cyan-300" />
            <span>{loading ? 'Inspecting...' : 'Analyze URL'}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        {error && (
          <div className="flex items-center space-x-2 p-3 rounded-lg bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs font-mono">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
        )}

        {/* Quick Sample Test Cases */}
        <div className="pt-2">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center space-x-1">
              <span>Quick Test Scenarios (1-Click Evaluation):</span>
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {SAMPLE_CASES.urls.map((sample) => (
              <button
                key={sample.id}
                type="button"
                onClick={() => handleSelectSample(sample)}
                disabled={loading}
                className={`text-xs px-3 py-1.5 rounded-lg border transition-all text-left font-mono hover:scale-102 ${sample.badgeColor} hover:bg-opacity-80`}
                title={sample.description}
              >
                <span className="font-semibold">{sample.label}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Cyber Radar Animation during scan */}
      {loading && <CyberScannerAnimation scanType="URL" />}

      {/* Scan Results Display */}
      {scanResult && !loading && (
        <ThreatResults
          result={scanResult}
          onReset={() => {
            setScanResult(null);
            setUrlInput('');
          }}
        />
      )}
    </div>
  );
}

