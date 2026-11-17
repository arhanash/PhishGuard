import React, { useState, useEffect } from 'react';
import { 
  History, Search, Filter, Trash2, Download, ExternalLink, 
  Globe, Mail, FileText, AlertTriangle, ShieldCheck, ShieldAlert,
  RefreshCw, CheckCircle2, ChevronLeft, ChevronRight
} from 'lucide-react';
import { api } from '../services/api';

export default function HistoryDashboard({ onSelectScan }) {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [scanType, setScanType] = useState('all');
  const [classification, setClassification] = useState('all');
  const [page, setPage] = useState(1);
  const limit = 15;

  const loadHistory = async () => {
    setLoading(true);
    try {
      const data = await api.getHistory({
        scan_type: scanType,
        classification: classification,
        search: search,
        limit: limit,
        offset: (page - 1) * limit,
      });
      setItems(data.items || []);
      setTotal(data.total || 0);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, [scanType, classification, page]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    loadHistory();
  };

  const handleDelete = async (id, e) => {
    e.stopPropagation();
    if (!window.confirm(`Are you sure you want to delete scan record #${id}?`)) return;
    try {
      await api.deleteScan(id);
      loadHistory();
    } catch (err) {
      alert('Delete failed: ' + err.message);
    }
  };

  const handleClearAll = async () => {
    if (!window.confirm('Are you sure you want to permanently clear the entire scan history?')) return;
    try {
      await api.clearHistory();
      setPage(1);
      loadHistory();
    } catch (err) {
      alert('Clear failed: ' + err.message);
    }
  };

  const totalPages = Math.ceil(total / limit) || 1;

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Top Controls */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center space-x-2">
            <History className="w-7 h-7 text-indigo-400" />
            <span>Forensic Scan Audit History</span>
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Search, filter, export, and inspect historical threat evaluations stored in the persistent database.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={loadHistory}
            className="p-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 transition-all"
            title="Refresh logs"
          >
            <RefreshCw className={`w-4 h-4 text-cyan-400 ${loading ? 'animate-spin' : ''}`} />
          </button>
          {items.length > 0 && (
            <button
              onClick={handleClearAll}
              className="flex items-center space-x-1.5 px-3 py-2 rounded-xl bg-rose-950/40 hover:bg-rose-900/60 border border-rose-500/30 text-rose-300 text-xs font-mono font-semibold transition-all"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Purge Audit Log</span>
            </button>
          )}
        </div>
      </div>

      {/* Filter Bar */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 backdrop-blur-xl flex flex-col md:flex-row items-stretch md:items-center gap-3">
        {/* Search */}
        <form onSubmit={handleSearchSubmit} className="flex-1 relative">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
            <Search className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search targets, domains, keywords..."
            className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-700/80 rounded-lg text-slate-100 placeholder-slate-500 text-xs font-mono focus:outline-none focus:border-cyan-400"
          />
        </form>

        {/* Scan Type Filter */}
        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono text-slate-400">Modality:</span>
          <select
            value={scanType}
            onChange={(e) => {
              setScanType(e.target.value);
              setPage(1);
            }}
            className="px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-400"
          >
            <option value="all">All Targets</option>
            <option value="url">URL Scans Only</option>
            <option value="email">Email Scans Only</option>
          </select>
        </div>

        {/* Classification Filter */}
        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono text-slate-400">Risk:</span>
          <select
            value={classification}
            onChange={(e) => {
              setClassification(e.target.value);
              setPage(1);
            }}
            className="px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-400"
          >
            <option value="all">All Severity</option>
            <option value="safe">Safe Only</option>
            <option value="suspicious">Suspicious Only</option>
            <option value="malicious">Malicious Only</option>
          </select>
        </div>
      </div>

      {/* History Table */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/80 backdrop-blur-xl overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/70 text-slate-400 uppercase text-[10px] tracking-wider">
                <th className="py-3 px-4">ID</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Target Entity</th>
                <th className="py-3 px-4">Risk Level</th>
                <th className="py-3 px-4 text-center">Score</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {loading ? (
                <tr>
                  <td colSpan="7" className="py-12 text-center text-slate-400">
                    <RefreshCw className="w-6 h-6 animate-spin mx-auto text-cyan-400 mb-2" />
                    Querying Audit Database...
                  </td>
                </tr>
              ) : items.length === 0 ? (
                <tr>
                  <td colSpan="7" className="py-12 text-center text-slate-500">
                    No matching scan records found. Run a new scan from the scanner tabs.
                  </td>
                </tr>
              ) : (
                items.map((row) => {
                  const isSafe = row.classification === 'Safe';
                  const isSusp = row.classification === 'Suspicious';
                  const isMal = row.classification === 'Malicious';
                  const pillClass = isSafe
                    ? 'border-emerald-500/40 text-emerald-400 bg-emerald-950/30'
                    : isSusp
                    ? 'border-amber-500/40 text-amber-400 bg-amber-950/30'
                    : 'border-rose-500/40 text-rose-400 bg-rose-950/30';

                  return (
                    <tr
                      key={row.id}
                      onClick={() => onSelectScan(row)}
                      className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                    >
                      <td className="py-3.5 px-4 text-slate-400">
                        #{row.id}
                      </td>
                      <td className="py-3.5 px-4 text-slate-400 whitespace-nowrap">
                        {new Date(row.timestamp).toLocaleDateString()} {new Date(row.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </td>
                      <td className="py-3.5 px-4">
                        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-[11px] text-slate-300">
                          {row.scan_type === 'url' ? (
                            <>
                              <Globe className="w-3 h-3 text-cyan-400" />
                              <span>URL</span>
                            </>
                          ) : (
                            <>
                              <Mail className="w-3 h-3 text-purple-400" />
                              <span>EMAIL</span>
                            </>
                          )}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-slate-200 max-w-xs truncate">
                        {row.target}
                      </td>
                      <td className="py-3.5 px-4">
                        <span className={`px-2.5 py-0.5 rounded text-[11px] font-bold border ${pillClass}`}>
                          {row.classification}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 text-center font-bold">
                        <span className={isMal ? 'text-rose-400' : isSusp ? 'text-amber-400' : 'text-emerald-400'}>
                          {row.risk_score}%
                        </span>
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <div className="flex items-center justify-end space-x-2" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => onSelectScan(row)}
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400"
                            title="Inspect details"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => api.downloadReport(row.id, 'txt')}
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
                            title="Download TXT Report"
                          >
                            <Download className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={(e) => handleDelete(row.id, e)}
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-rose-950 text-slate-400 hover:text-rose-400"
                            title="Delete entry"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="p-4 border-t border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400">
          <span>
            Showing {items.length} of {total} records
          </span>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="p-1.5 rounded-lg bg-slate-950 border border-slate-800 disabled:opacity-40 hover:bg-slate-800 text-slate-300"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span>
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="p-1.5 rounded-lg bg-slate-950 border border-slate-800 disabled:opacity-40 hover:bg-slate-800 text-slate-300"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

