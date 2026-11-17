const API_BASE = '/api';

export const api = {
  async checkHealth() {
    try {
      const res = await fetch(`${API_BASE}/health`);
      if (!res.ok) throw new Error('Health check failed');
      return await res.json();
    } catch (err) {
      console.error('API health check error:', err);
      return { status: 'offline' };
    }
  },

  async scanUrl(url) {
    const res = await fetch(`${API_BASE}/scan/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to scan URL');
    }
    return await res.json();
  },

  async scanEmail({ raw_content, subject = '', sender = '' }) {
    const res = await fetch(`${API_BASE}/scan/email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw_content, subject, sender }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to scan email content');
    }
    return await res.json();
  },

  async getHistory({ scan_type = 'all', classification = 'all', search = '', limit = 50, offset = 0 } = {}) {
    const params = new URLSearchParams({
      scan_type,
      classification,
      search,
      limit: limit.toString(),
      offset: offset.toString(),
    });
    const res = await fetch(`${API_BASE}/history?${params.toString()}`);
    if (!res.ok) throw new Error('Failed to load history');
    return await res.json();
  },

  async getScanDetails(scanId) {
    const res = await fetch(`${API_BASE}/history/${scanId}`);
    if (!res.ok) throw new Error(`Scan #${scanId} not found`);
    return await res.json();
  },

  async deleteScan(scanId) {
    const res = await fetch(`${API_BASE}/history/${scanId}`, {
      method: 'DELETE',
    });
    if (!res.ok) throw new Error('Failed to delete scan record');
    return await res.json();
  },

  async clearHistory() {
    const res = await fetch(`${API_BASE}/history`, {
      method: 'DELETE',
    });
    if (!res.ok) throw new Error('Failed to clear history');
    return await res.json();
  },

  async getDashboardStats() {
    const res = await fetch(`${API_BASE}/dashboard/stats`);
    if (!res.ok) throw new Error('Failed to load dashboard stats');
    return await res.json();
  },

  async downloadReport(scanId, format = 'txt') {
    const res = await fetch(`${API_BASE}/report/${scanId}/download?format=${format}`);
    if (!res.ok) throw new Error('Failed to download report');
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard_report_${scanId}.${format}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  },

  async getSampleCases() {
    const res = await fetch(`${API_BASE}/sample-cases`);
    if (!res.ok) throw new Error('Failed to load sample cases');
    return await res.json();
  }
};

