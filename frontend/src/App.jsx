import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import UrlScanner from './components/UrlScanner';
import EmailScanner from './components/EmailScanner';
import AnalyticsView from './components/AnalyticsView';
import HistoryDashboard from './components/HistoryDashboard';
import SecurityGuide from './components/SecurityGuide';
import ThreatResults from './components/ThreatResults';
import { api } from './services/api';
import { ShieldCheck, ArrowLeft, Terminal, ShieldAlert } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('url');
  const [systemStatus, setSystemStatus] = useState('online');
  const [inspectedScan, setInspectedScan] = useState(null);

  // Check health on mount
  useEffect(() => {
    const checkEngine = async () => {
      const res = await api.checkHealth();
      setSystemStatus(res.status === 'online' ? 'online' : 'offline');
    };
    checkEngine();
    const interval = setInterval(checkEngine, 30000); // periodic check
    return () => clearInterval(interval);
  }, []);

  const handleSelectScanForInspection = (scan) => {
    setInspectedScan(scan);
  };

  const handleTabChange = (newTab) => {
    setInspectedScan(null);
    setActiveTab(newTab);
  };

  return (
    <div className="min-h-screen bg-[#060913] text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-black">
      {/* Background Decorative Cyber Gradients */}
      <div className="fixed inset-0 pointer-events-none z-0">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-indigo-600/10 rounded-full blur-3xl" />
        <div className="absolute top-1/3 right-1/4 w-96 h-96 bg-purple-600/10 rounded-full blur-3xl" />
        <div className="absolute bottom-10 left-1/3 w-80 h-80 bg-cyan-600/10 rounded-full blur-3xl" />
      </div>

      {/* Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={handleTabChange}
        systemStatus={systemStatus}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 relative z-10">
        {/* If a historical scan is being inspected, render it directly with a Back button */}
        {inspectedScan ? (
          <div className="space-y-6 animate-in fade-in duration-200">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <button
                onClick={() => setInspectedScan(null)}
                className="inline-flex items-center space-x-2 px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono transition-all"
              >
                <ArrowLeft className="w-4 h-4 text-cyan-400" />
                <span>Return to Dashboard</span>
              </button>
              <span className="text-xs font-mono text-slate-400">
                Inspecting Historical Forensic Record #{inspectedScan.id}
              </span>
            </div>

            <ThreatResults
              result={inspectedScan}
              onReset={() => setInspectedScan(null)}
            />
          </div>
        ) : (
          <>
            {activeTab === 'url' && (
              <UrlScanner onScanComplete={() => {}} />
            )}

            {activeTab === 'email' && (
              <EmailScanner onScanComplete={() => {}} />
            )}

            {activeTab === 'analytics' && (
              <AnalyticsView onSelectScan={handleSelectScanForInspection} />
            )}

            {activeTab === 'history' && (
              <HistoryDashboard onSelectScan={handleSelectScanForInspection} />
            )}

            {activeTab === 'guide' && (
              <SecurityGuide />
            )}
          </>
        )}
      </main>

      {/* High-Tech Cybersecurity Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950/90 py-6 text-xs text-slate-400 font-mono relative z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <span className="text-slate-300 font-semibold tracking-wide">
              PhishGuard AI
            </span>
            <span className="text-slate-600">|</span>
            <span>B.Tech Cybersecurity Capstone Project</span>
          </div>

          <div className="flex items-center space-x-6 text-[11px] text-slate-400">
            <span>Ensemble Random Forest & NLP Engine</span>
            <span>SQLite Forensic Storage</span>
            <span>FastAPI Backend Core</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
