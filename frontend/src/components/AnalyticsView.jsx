import React, { useState, useEffect } from 'react';
import { 
  BarChart3, ShieldCheck, ShieldAlert, AlertTriangle, 
  Activity, RefreshCw, Globe, Mail, TrendingUp, Shield 
} from 'lucide-react';
import { 
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, 
  Tooltip, ResponsiveContainer, Legend 
} from 'recharts';
import { api } from '../services/api';

const COLORS = {
  Safe: '#10b981',       // Emerald
  Suspicious: '#f59e0b', // Amber
  Malicious: '#f43f5e',  // Rose
};

export default function AnalyticsView({ onSelectScan }) {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadStats = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getDashboardStats();
      setStats(data);
    } catch (err) {
      console.error(err);
      setError(err.message || 'Failed to load threat telemetry.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStats();
  }, []);

  if (loading && !stats) {
    return (
      <div className="flex flex-col items-center justify-center p-16 space-y-4">
        <Activity className="w-8 h-8 text-cyan-400 animate-spin" />
        <p className="text-sm font-mono text-slate-400">Loading Cybersecurity Telemetry...</p>
      </div>
    );
  }

  if (error && !stats) {
    return (
      <div className="p-8 text-center text-rose-400 font-mono space-y-3">
        <p>{error}</p>
        <button
          onClick={loadStats}
          className="px-4 py-2 bg-slate-800 rounded-lg text-slate-200 text-xs hover:bg-slate-700"
        >
          Retry
        </button>
      </div>
    );
  }

  const {
    total_scans = 0,
    safe_scans = 0,
    suspicious_scans = 0,
    malicious_scans = 0,
    avg_risk_score = 0,
    url_scans_count = 0,
    email_scans_count = 0,
    recent_scans = [],
    attack_type_distribution = {}
  } = stats || {};

  // Donut chart data
  const pieData = [
    { name: 'Safe', value: safe_scans },
    { name: 'Suspicious', value: suspicious_scans },
    { name: 'Malicious', value: malicious_scans },
  ].filter(d => d.value > 0);

  // Attack category data for bar chart
  const barData = Object.entries(attack_type_distribution).map(([cat, count]) => ({
    category: cat.length > 18 ? cat.substring(0, 16) + '..' : cat,
    fullName: cat,
    count: count
  }));

  const safePct = total_scans > 0 ? Math.round((safe_scans / total_scans) * 100) : 0;
  const malPct = total_scans > 0 ? Math.round((malicious_scans / total_scans) * 100) : 0;

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Threat Intelligence & Analytics Dashboard
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Aggregated metrics on URL and email attack vectors, machine learning classification rates, and real-time threat telemetry.
          </p>
        </div>
        <button
          onClick={loadStats}
          disabled={loading}
          className="inline-flex items-center space-x-2 px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono font-medium transition-all"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Telemetry</span>
        </button>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Total Scans */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 backdrop-blur-xl relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono uppercase">
            <span>Total Scans</span>
            <Activity className="w-4 h-4 text-indigo-400" />
          </div>
          <p className="text-3xl font-black font-mono text-white mt-2">
            {total_scans}
          </p>
          <div className="text-[11px] font-mono text-slate-400 mt-1 flex items-center space-x-2">
            <span>URLs: {url_scans_count}</span>
            <span>•</span>
            <span>Emails: {email_scans_count}</span>
          </div>
        </div>

        {/* Safe Ratio */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-emerald-500/30 backdrop-blur-xl relative overflow-hidden">
          <div className="flex items-center justify-between text-emerald-400 text-xs font-mono uppercase">
            <span>Safe Targets</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <p className="text-3xl font-black font-mono text-emerald-400 mt-2">
            {safe_scans}
          </p>
          <p className="text-[11px] font-mono text-emerald-400/80 mt-1">
            {safePct}% Benign baseline
          </p>
        </div>

        {/* Suspicious */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-amber-500/30 backdrop-blur-xl relative overflow-hidden">
          <div className="flex items-center justify-between text-amber-400 text-xs font-mono uppercase">
            <span>Suspicious</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <p className="text-3xl font-black font-mono text-amber-400 mt-2">
            {suspicious_scans}
          </p>
          <p className="text-[11px] font-mono text-amber-400/80 mt-1">
            Anomalous patterns
          </p>
        </div>

        {/* Malicious Intercepts */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-rose-500/40 backdrop-blur-xl relative overflow-hidden">
          <div className="flex items-center justify-between text-rose-400 text-xs font-mono uppercase">
            <span>Malicious Intercepts</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <p className="text-3xl font-black font-mono text-rose-400 mt-2">
            {malicious_scans}
          </p>
          <p className="text-[11px] font-mono text-rose-400/80 mt-1">
            {malPct}% High threat density
          </p>
        </div>

        {/* Avg Risk Index */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-cyan-500/30 backdrop-blur-xl relative overflow-hidden">
          <div className="flex items-center justify-between text-cyan-400 text-xs font-mono uppercase">
            <span>Avg Risk Index</span>
            <TrendingUp className="w-4 h-4 text-cyan-400" />
          </div>
          <p className="text-3xl font-black font-mono text-cyan-400 mt-2">
            {avg_risk_score}%
          </p>
          <p className="text-[11px] font-mono text-slate-400 mt-1">
            Enterprise mean score
          </p>
        </div>
      </div>

      {/* Visual Analytics Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Donut Chart: Risk Distribution */}
        <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 backdrop-blur-xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-base font-bold text-white tracking-wide">
              Risk Level Distribution
            </h3>
            <span className="text-xs font-mono text-slate-400">Class Proportions</span>
          </div>

          <div className="h-64 w-full flex items-center justify-center">
            {pieData.length === 0 ? (
              <p className="text-xs font-mono text-slate-500">No scan data to chart yet.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={85}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[entry.name] || '#6366f1'} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      color: '#f8fafc',
                      fontSize: '12px',
                    }}
                  />
                  <Legend
                    formatter={(value) => (
                      <span className="text-xs font-mono text-slate-300">{value}</span>
                    )}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Bar Chart: Threat Vectors by Category */}
        <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 backdrop-blur-xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-base font-bold text-white tracking-wide">
              Threat Vectors Triggered
            </h3>
            <span className="text-xs font-mono text-slate-400">By Category</span>
          </div>

          <div className="h-64 w-full flex items-center justify-center">
            {barData.length === 0 ? (
              <p className="text-xs font-mono text-slate-500">No threat indicators logged yet.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barData} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                  <XAxis
                    dataKey="category"
                    stroke="#64748b"
                    fontSize={10}
                    interval={0}
                    angle={-20}
                    textAnchor="end"
                  />
                  <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      color: '#f8fafc',
                      fontSize: '12px',
                    }}
                  />
                  <Bar dataKey="count" fill="#818cf8" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Recent Telemetry Stream */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 backdrop-blur-xl space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <h3 className="text-base font-bold text-white tracking-wide">
              Recent Threat Audit Stream
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">Latest 8 Events</span>
        </div>

        {recent_scans.length === 0 ? (
          <p className="text-xs font-mono text-slate-500 py-4 text-center">
            No recent scans recorded. Use the URL or Email Scanner to begin.
          </p>
        ) : (
          <div className="divide-y divide-slate-800/60">
            {recent_scans.map((scan) => {
              const isCrit = scan.classification === 'Malicious';
              const isSusp = scan.classification === 'Suspicious';
              const badgeClass = isCrit
                ? 'text-rose-400 bg-rose-950/40 border-rose-500/40'
                : isSusp
                ? 'text-amber-400 bg-amber-950/40 border-amber-500/40'
                : 'text-emerald-400 bg-emerald-950/40 border-emerald-500/40';

              return (
                <div
                  key={scan.id}
                  className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-slate-800/30 px-2 rounded-lg transition-colors cursor-pointer"
                  onClick={() => onSelectScan && onSelectScan(scan)}
                >
                  <div className="flex items-center space-x-3 min-w-0">
                    <span className="p-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-400">
                      {scan.scan_type === 'url' ? <Globe className="w-4 h-4 text-cyan-400" /> : <Mail className="w-4 h-4 text-purple-400" />}
                    </span>
                    <div className="truncate">
                      <p className="text-xs sm:text-sm font-mono text-slate-200 truncate max-w-md">
                        {scan.target}
                      </p>
                      <span className="text-[11px] text-slate-500 font-mono">
                        {new Date(scan.timestamp).toLocaleString()}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-3 self-end sm:self-center">
                    <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold border ${badgeClass}`}>
                      {scan.classification} ({scan.risk_score}%)
                    </span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        if (onSelectScan) onSelectScan(scan);
                      }}
                      className="text-xs text-cyan-400 hover:text-cyan-300 font-mono"
                    >
                      Inspect →
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

