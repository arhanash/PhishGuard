import React, { useState } from 'react';
import { Mail, ArrowRight, Sparkles, Shield, AlertCircle, FileText, UserCheck, X, Clipboard } from 'lucide-react';
import { api } from '../services/api';
import { SAMPLE_CASES } from '../sampleData';
import CyberScannerAnimation from './CyberScannerAnimation';
import ThreatResults from './ThreatResults';

export default function EmailScanner({ onScanComplete }) {
  const [subject, setSubject] = useState('');
  const [sender, setSender] = useState('');
  const [rawContent, setRawContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [scanResult, setScanResult] = useState(null);

  const handleScan = async (sampleData = null) => {
    const finalContent = (sampleData?.body || rawContent).trim();
    const finalSubject = (sampleData?.subject || subject).trim();
    const finalSender = (sampleData?.sender || sender).trim();

    if (!finalContent) {
      setError('Please paste or write email body text or headers to analyze.');
      return;
    }

    setError(null);
    setLoading(true);
    setScanResult(null);

    try {
      const [res] = await Promise.all([
        api.scanEmail({
          raw_content: finalContent,
          subject: finalSubject,
          sender: finalSender,
        }),
        new Promise((resolve) => setTimeout(resolve, 1400)),
      ]);
      setScanResult(res);
      if (onScanComplete) onScanComplete(res);
    } catch (err) {
      console.error(err);
      setError(err.message || 'An error occurred while inspecting the email.');
    } finally {
      setLoading(false);
    }
  };

  const handleSelectSample = (sample) => {
    setSubject(sample.subject);
    setSender(sample.sender);
    setRawContent(sample.body);
    handleScan(sample);
  };

  const handleClear = () => {
    setSubject('');
    setSender('');
    setRawContent('');
    setScanResult(null);
    setError(null);
  };

  return (
    <div className="space-y-8">
      {/* Hero Headline */}
      <div className="text-center max-w-3xl mx-auto space-y-3">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-gradient-to-r from-purple-500/10 via-pink-500/10 to-indigo-500/10 border border-purple-500/30 text-purple-300 text-xs font-mono">
          <Sparkles className="w-3.5 h-3.5" />
          <span>NLP Text Semantics & Deep Hyperlink Inspection Engine</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          AI-Powered Phishing Email & BEC Detection
        </h1>
        <p className="text-sm sm:text-base text-slate-400">
          Unmask sender spoofing, artificial urgency tactics, credential theft solicitations, Business Email Compromise (BEC), and recursive embedded link threats.
        </p>
      </div>

      {/* Input Box Card */}
      <div className="max-w-4xl mx-auto bg-slate-900/80 border border-slate-800 rounded-2xl p-4 sm:p-6 backdrop-blur-xl cyber-glow-purple shadow-2xl space-y-4">
        {/* Quick Test Scenarios */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
              One-Click Phishing Scenarios:
            </span>
            {(subject || sender || rawContent) && !loading && (
              <button
                type="button"
                onClick={handleClear}
                className="text-xs text-slate-400 hover:text-slate-200 flex items-center space-x-1"
              >
                <X className="w-3.5 h-3.5" />
                <span>Reset Form</span>
              </button>
            )}
          </div>
          <div className="flex flex-wrap gap-2">
            {SAMPLE_CASES.emails.map((sample) => (
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

        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleScan();
          }}
          className="space-y-3 pt-2"
        >
          {/* Header Row: Subject & Sender */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">
                Sender Email Address / Display Header:
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                  <UserCheck className="w-4 h-4 text-purple-400" />
                </div>
                <input
                  type="text"
                  value={sender}
                  onChange={(e) => setSender(e.target.value)}
                  placeholder="e.g. PayPal Support <support@suspicious-domain.xyz>"
                  disabled={loading}
                  className="w-full pl-9 pr-3 py-2.5 bg-slate-950/90 border border-slate-700/80 rounded-xl text-slate-100 placeholder-slate-500 text-xs focus:outline-none focus:border-purple-400 focus:ring-1 focus:ring-purple-400 font-mono"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">
                Email Subject Line:
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                  <Mail className="w-4 h-4 text-indigo-400" />
                </div>
                <input
                  type="text"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  placeholder="e.g. URGENT: Action Required on Your Account..."
                  disabled={loading}
                  className="w-full pl-9 pr-3 py-2.5 bg-slate-950/90 border border-slate-700/80 rounded-xl text-slate-100 placeholder-slate-500 text-xs focus:outline-none focus:border-purple-400 focus:ring-1 focus:ring-purple-400 font-mono"
                />
              </div>
            </div>
          </div>

          {/* Email Body */}
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">
              Email Body Content or Full Raw MIME/Text:
            </label>
            <textarea
              rows={6}
              value={rawContent}
              onChange={(e) => setRawContent(e.target.value)}
              placeholder="Paste the full email text, suspicious message, or raw headers here..."
              disabled={loading}
              className="w-full p-3 bg-slate-950/90 border border-slate-700/80 rounded-xl text-slate-100 placeholder-slate-500 text-xs focus:outline-none focus:border-purple-400 focus:ring-1 focus:ring-purple-400 font-mono leading-relaxed"
            />
          </div>

          {error && (
            <div className="flex items-center space-x-2 p-3 rounded-lg bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs font-mono">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
              <span>{error}</span>
            </div>
          )}

          <div className="flex items-center justify-end pt-2">
            <button
              type="submit"
              disabled={loading}
              className="flex items-center justify-center space-x-2 px-6 py-3 rounded-xl bg-gradient-to-r from-purple-600 via-indigo-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 text-white font-semibold text-sm shadow-lg shadow-purple-600/30 transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              <Shield className="w-4 h-4 text-cyan-300" />
              <span>{loading ? 'Analyzing Content...' : 'Analyze Email Threat'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </form>
      </div>

      {/* Scanning Animation */}
      {loading && <CyberScannerAnimation scanType="EMAIL" />}

      {/* Results */}
      {scanResult && !loading && (
        <ThreatResults
          result={scanResult}
          onReset={handleClear}
        />
      )}
    </div>
  );
}

