// frontend/src/components/GitHubRepoBrowser.jsx
// Browse and select GitHub repositories to scan

import React, { useState, useEffect } from 'react';
import { GitBranch, ChevronRight, AlertCircle, Loader, Star, Lock, Code2, RefreshCw } from 'lucide-react';

const API_URL = 'http://localhost:4000';

export default function GitHubRepoBrowser({ onSelectRepo, isLoading: externalLoading }) {
  const [repos, setRepos] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedRepo, setSelectedRepo] = useState(null);
  const [page, setPage] = useState(1);
  const [hasNextPage, setHasNextPage] = useState(false);
  const [branches, setBranches] = useState([]);
  const [selectedBranch, setSelectedBranch] = useState('main');
  const [loadingBranches, setLoadingBranches] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);

  // Check authentication on mount
  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    try {
      const res = await fetch(`${API_URL}/auth/github/session`, { credentials: 'include' });
      if (res.ok) {
        const data = await res.json();
        if (data.authenticated) {
          setAuthenticated(true);
          fetchRepos(1);
        }
      }
    } catch {
      // Not authenticated
    }
  };

  const fetchRepos = async (pageNum) => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch(
        `${API_URL}/github/repos?page=${pageNum}&perPage=30`,
        {
          credentials: 'include',
        }
      );

      if (!response.ok) throw new Error('Failed to fetch repositories');

      const data = await response.json();
      setRepos(data.repos || []);
      setPage(pageNum);
      setHasNextPage(data.hasNextPage || false);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Fetch branches for selected repo
  const handleSelectRepo = async (repo) => {
    try {
      setSelectedRepo(repo);
      setLoadingBranches(true);

      const response = await fetch(
        `${API_URL}/github/repos/${repo.owner}/${repo.name}/branches`,
        {
          credentials: 'include',
        }
      );

      if (!response.ok) throw new Error('Failed to fetch branches');

      const data = await response.json();
      setBranches(data.branches || []);
      
      // Set default branch
      const defaultBranch = data.branches.find(b => b.isDefault) || data.branches[0];
      setSelectedBranch(defaultBranch?.name || repo.defaultBranch || 'main');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingBranches(false);
    }
  };

  // Scan selected repository
  const handleScan = async () => {
    if (!selectedRepo) return;

    try {
      onSelectRepo({
        owner: selectedRepo.owner,
        repo: selectedRepo.name,
        branch: selectedBranch,
        name: selectedRepo.name,
        url: selectedRepo.url,
      });
    } catch (err) {
      setError(err.message);
    }
  };

  if (!authenticated) {
    return (
      <div className="repo-browser-container">
        <div className="alert alert-info">
          <AlertCircle size={20} />
          <span>Please login with GitHub first to browse repositories.</span>
        </div>
      </div>
    );
  }

  return (
    <div className="repo-browser-container">
      <div className="repo-browser-header">
        <h3>
          <GitBranch size={20} />
          Your Repositories
        </h3>
        <button
          onClick={() => fetchRepos(1)}
          disabled={loading}
          className="btn-refresh"
          title="Refresh repository list"
        >
          <RefreshCw size={16} className={loading ? 'spinning' : ''} />
        </button>
      </div>

      {error && (
        <div className="alert alert-error">
          <AlertCircle size={20} />
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="loading-state">
          <Loader size={32} className="spinning" />
          <p>Loading repositories...</p>
        </div>
      ) : (
        <>
          <div className="repos-list">
            {repos.length === 0 ? (
              <div className="empty-state">
                <Code2 size={48} />
                <p>No repositories found</p>
              </div>
            ) : (
              repos.map((repo) => (
                <div
                  key={repo.id}
                  className={`repo-item ${selectedRepo?.id === repo.id ? 'selected' : ''}`}
                  onClick={() => handleSelectRepo(repo)}
                >
                  <div className="repo-info">
                    <div className="repo-name">
                      {repo.isPrivate && <Lock size={14} title="Private repository" />}
                      {repo.name}
                    </div>
                    {repo.description && (
                      <p className="repo-description">{repo.description}</p>
                    )}
                    <div className="repo-meta">
                      {repo.language && (
                        <span className="repo-language">{repo.language}</span>
                      )}
                      {repo.starsCount > 0 && (
                        <span className="repo-stars">
                          <Star size={12} />
                          {repo.starsCount}
                        </span>
                      )}
                      <span className="repo-updated">
                        Updated {new Date(repo.updatedAt).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                  <ChevronRight size={20} className="repo-chevron" />
                </div>
              ))
            )}
          </div>

          {selectedRepo && (
            <div className="repo-details-panel">
              <div className="details-header">
                <h4>Repository Details</h4>
                <p className="selected-repo-name">{selectedRepo.fullName}</p>
              </div>

              {loadingBranches ? (
                <div className="loading-state-small">
                  <Loader size={20} className="spinning" />
                  <span>Loading branches...</span>
                </div>
              ) : (
                <>
                  <div className="branch-selector">
                    <label htmlFor="branch-select">Select Branch:</label>
                    <select
                      id="branch-select"
                      value={selectedBranch}
                      onChange={(e) => setSelectedBranch(e.target.value)}
                      className="branch-select"
                    >
                      {branches.map((branch) => (
                        <option key={branch.name} value={branch.name}>
                          {branch.name}
                          {branch.isDefault ? ' (default)' : ''}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="repo-stats">
                    <div className="stat">
                      <span className="stat-label">Repository</span>
                      <span className="stat-value">{selectedRepo.name}</span>
                    </div>
                    <div className="stat">
                      <span className="stat-label">Branch</span>
                      <span className="stat-value">{selectedBranch}</span>
                    </div>
                    <div className="stat">
                      <span className="stat-label">Language</span>
                      <span className="stat-value">{selectedRepo.language || 'Unknown'}</span>
                    </div>
                  </div>

                  <button
                    onClick={handleScan}
                    disabled={externalLoading}
                    className="btn btn-primary btn-scan"
                  >
                    {externalLoading ? 'Scanning...' : 'Scan Repository'}
                  </button>
                </>
              )}
            </div>
          )}

          {/* Pagination */}
          {repos.length > 0 && (
            <div className="pagination">
              <button
                onClick={() => fetchRepos(page - 1)}
                disabled={page === 1 || loading}
                className="btn btn-sm"
              >
                Previous
              </button>
              <span className="page-info">Page {page}</span>
              <button
                onClick={() => fetchRepos(page + 1)}
                disabled={!hasNextPage || loading}
                className="btn btn-sm"
              >
                Next
              </button>
            </div>
          )}
        </>
      )}

      <style jsx>{`
        .repo-browser-container {
          display: flex;
          flex-direction: column;
          gap: 16px;
          padding: 20px;
          background: white;
          border-radius: 8px;
          border: 1px solid #e0e0e0;
        }

        .repo-browser-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 12px;
        }

        .repo-browser-header h3 {
          display: flex;
          align-items: center;
          gap: 8px;
          margin: 0;
          font-size: 18px;
          color: #333;
        }

        .btn-refresh {
          background: none;
          border: none;
          cursor: pointer;
          padding: 8px;
          color: #007bff;
          display: flex;
          align-items: center;
          border-radius: 4px;
          transition: background 0.2s;
        }

        .btn-refresh:hover {
          background: #f0f0f0;
        }

        .btn-refresh:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        .spinning {
          animation: spin 1s linear infinite;
        }

        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }

        .alert {
          display: flex;
          gap: 12px;
          padding: 12px 16px;
          border-radius: 6px;
          font-size: 14px;
        }

        .alert-error {
          background: #fee;
          color: #c00;
          border: 1px solid #fcc;
        }

        .alert-info {
          background: #eff;
          color: #009;
          border: 1px solid #ccf;
        }

        .loading-state {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 12px;
          padding: 40px;
          color: #666;
        }

        .loading-state-small {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 16px;
          color: #666;
          font-size: 14px;
        }

        .repos-list {
          display: flex;
          flex-direction: column;
          gap: 8px;
          max-height: 400px;
          overflow-y: auto;
          border: 1px solid #e0e0e0;
          border-radius: 6px;
        }

        .repo-item {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 12px;
          border-bottom: 1px solid #f0f0f0;
          cursor: pointer;
          transition: background 0.2s;
        }

        .repo-item:hover {
          background: #f8f9fa;
        }

        .repo-item.selected {
          background: #e7f3ff;
          border-left: 4px solid #007bff;
        }

        .repo-info {
          flex: 1;
          display: flex;
          flex-direction: column;
          gap: 6px;
        }

        .repo-name {
          display: flex;
          align-items: center;
          gap: 6px;
          font-weight: 600;
          color: #333;
        }

        .repo-description {
          font-size: 12px;
          color: #666;
          margin: 0;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }

        .repo-meta {
          display: flex;
          gap: 12px;
          font-size: 12px;
          color: #999;
        }

        .repo-language {
          background: #f0f0f0;
          padding: 2px 8px;
          border-radius: 12px;
        }

        .repo-stars {
          display: flex;
          align-items: center;
          gap: 4px;
        }

        .repo-chevron {
          color: #007bff;
          opacity: 0;
          transition: opacity 0.2s;
        }

        .repo-item:hover .repo-chevron {
          opacity: 1;
        }

        .empty-state {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 12px;
          padding: 40px;
          color: #999;
        }

        .repo-details-panel {
          display: flex;
          flex-direction: column;
          gap: 16px;
          padding: 16px;
          background: #f8f9fa;
          border-radius: 6px;
          border: 1px solid #e0e0e0;
        }

        .details-header {
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .details-header h4 {
          margin: 0;
          font-size: 14px;
          color: #999;
          font-weight: 600;
          text-transform: uppercase;
        }

        .selected-repo-name {
          margin: 0;
          font-size: 16px;
          color: #333;
          font-weight: 600;
        }

        .branch-selector {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .branch-selector label {
          font-size: 14px;
          font-weight: 600;
          color: #333;
        }

        .branch-select {
          padding: 8px 12px;
          border: 1px solid #ddd;
          border-radius: 4px;
          font-size: 14px;
          background: white;
          cursor: pointer;
        }

        .repo-stats {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 12px;
        }

        .stat {
          display: flex;
          flex-direction: column;
          gap: 4px;
          padding: 12px;
          background: white;
          border-radius: 4px;
          border: 1px solid #e0e0e0;
        }

        .stat-label {
          font-size: 12px;
          color: #999;
          font-weight: 600;
          text-transform: uppercase;
        }

        .stat-value {
          font-size: 14px;
          color: #333;
          font-weight: 600;
        }

        .btn {
          padding: 10px 16px;
          border-radius: 6px;
          border: none;
          font-size: 14px;
          cursor: pointer;
          font-weight: 600;
          transition: all 0.2s;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
        }

        .btn-primary {
          background: #007bff;
          color: white;
        }

        .btn-primary:hover:not(:disabled) {
          background: #0056b3;
        }

        .btn-sm {
          padding: 8px 12px;
          font-size: 12px;
        }

        .btn:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        .btn-scan {
          width: 100%;
        }

        .pagination {
          display: flex;
          justify-content: center;
          align-items: center;
          gap: 12px;
          margin-top: 12px;
        }

        .page-info {
          font-size: 14px;
          color: #666;
        }
      `}</style>
    </div>
  );
}
