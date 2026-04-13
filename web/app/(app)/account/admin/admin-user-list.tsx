'use client';

import { useState, useMemo } from 'react';

export interface AdminUser {
  id: string;
  email: string;
  display_name: string | null;
  avatar_url: string | null;
  tier: string;
  role: string;
  chat_count_today: number;
  preferred_model: string;
  openrouter_usage_usd: number;
  openrouter_usage_limit_usd: number;
  has_openrouter_key: boolean;
  has_claude_key: boolean;
  has_openai_key: boolean;
  stripe_customer_id: string | null;
  provider: string;
  last_sign_in: string | null;
  created_at: string;
  updated_at: string;
  conversations_count: number;
  reports_count: number;
  tokens_total: number;
  tokens_active: number;
}

type TierFilter = 'all' | 'admin' | 'pro' | 'free' | 'blocked';

function timeAgo(date: string | null): string {
  if (!date) return 'never';
  const seconds = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
  return new Date(date).toLocaleDateString();
}

function isNew(date: string): boolean {
  return Date.now() - new Date(date).getTime() < 7 * 86400 * 1000;
}

function getInitials(name: string | null, email: string): string {
  if (name) {
    return name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2);
  }
  return email[0]?.toUpperCase() || '?';
}

function providerLabel(provider: string): string {
  if (provider === 'github') return 'GitHub';
  if (provider === 'google') return 'Google';
  return 'Email';
}

export function AdminUserList({ users: initialUsers, currentUserId }: { users: AdminUser[]; currentUserId: string }) {
  const [users, setUsers] = useState(initialUsers);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<TierFilter>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [updating, setUpdating] = useState<string | null>(null);

  const counts = useMemo(() => ({
    all: users.length,
    admin: users.filter(u => u.role === 'admin').length,
    pro: users.filter(u => u.tier === 'pro').length,
    free: users.filter(u => u.tier === 'free').length,
    blocked: users.filter(u => u.tier === 'blocked').length,
  }), [users]);

  const filtered = useMemo(() => {
    let result = users;
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(u =>
        (u.display_name || '').toLowerCase().includes(q) ||
        u.email.toLowerCase().includes(q)
      );
    }
    if (filter === 'admin') {
      result = result.filter(u => u.role === 'admin');
    } else if (filter !== 'all') {
      result = result.filter(u => u.tier === filter);
    }
    return result;
  }, [users, search, filter]);

  async function handleAction(userId: string, action: string, value?: string) {
    if (action === 'set_tier' && value === 'blocked') {
      if (!window.confirm('Block this user? They will lose access to all features.')) return;
    }
    if (action === 'set_role' && value === 'admin') {
      if (!window.confirm('Grant admin access to this user?')) return;
    }
    setUpdating(userId);
    try {
      const res = await fetch('/api/admin/update-user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, action, value }),
      });
      const data = await res.json();
      if (data.success) {
        setUsers(prev => prev.map(u => {
          if (u.id !== userId) return u;
          if (action === 'set_tier') return { ...u, tier: value! };
          if (action === 'set_role') return { ...u, role: value! };
          if (action === 'reset_chat_count') return { ...u, chat_count_today: 0 };
          return u;
        }));
      } else {
        alert(data.error || 'Action failed');
      }
    } catch {
      alert('Network error');
    }
    setUpdating(null);
  }

  function tierBadgeClass(tier: string) {
    switch (tier) {
      case 'admin': return 'bg-amber/20 text-amber border-amber/30';
      case 'pro': return 'bg-green/20 text-green border-green/30';
      case 'blocked': return 'bg-red/20 text-red border-red/30';
      default: return 'bg-card2 text-text-dim border-border';
    }
  }

  const filterPills: { key: TierFilter; label: string }[] = [
    { key: 'all', label: 'All' },
    { key: 'admin', label: 'Admin' },
    { key: 'pro', label: 'Pro' },
    { key: 'free', label: 'Free' },
    { key: 'blocked', label: 'Blocked' },
  ];

  return (
    <div>
      {/* Search + Filters */}
      <div className="mb-6 space-y-3">
        <div className="relative">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-dim" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by name or email..."
            className="w-full bg-bg2 border border-border focus:border-amber/50 rounded-[var(--radius-button)] pl-10 pr-4 py-2.5 text-text placeholder:text-text-dim/50 outline-none transition-colors font-[family-name:var(--font-mono)] text-sm"
          />
        </div>
        <div className="flex items-center gap-1.5 flex-wrap">
          {filterPills.map(p => (
            <button
              key={p.key}
              onClick={() => setFilter(p.key)}
              className={`text-xs font-[family-name:var(--font-mono)] px-3 py-1.5 rounded-full border transition-colors ${
                filter === p.key
                  ? 'bg-card2 border-amber/50 text-amber'
                  : 'bg-card border-border text-text-dim hover:border-border-bright hover:text-text'
              }`}
            >
              {p.label} ({counts[p.key]})
            </button>
          ))}
        </div>
      </div>

      {/* Result count */}
      <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] mb-3">
        {filtered.length} user{filtered.length !== 1 ? 's' : ''}
      </div>

      {/* User cards */}
      <div className="space-y-2">
        {filtered.map(user => {
          const isExpanded = expandedId === user.id;
          const isSelf = user.id === currentUserId;
          const isUpdating = updating === user.id;
          const usagePct = user.openrouter_usage_limit_usd > 0
            ? Math.min(100, (user.openrouter_usage_usd / user.openrouter_usage_limit_usd) * 100)
            : 0;

          return (
            <div
              key={user.id}
              className="bg-card border border-border rounded-[var(--radius-card)] overflow-hidden transition-colors hover:border-border-bright"
            >
              {/* Main row — clickable to expand */}
              <button
                onClick={() => setExpandedId(isExpanded ? null : user.id)}
                className="w-full px-4 py-3 flex items-center gap-3 text-left"
              >
                {/* Avatar */}
                <div className="w-9 h-9 rounded bg-card2 border border-border flex items-center justify-center shrink-0">
                  <span className="text-xs font-bold text-text-dim font-[family-name:var(--font-mono)]">
                    {getInitials(user.display_name, user.email)}
                  </span>
                </div>

                {/* Info */}
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="text-text-bright text-sm font-medium truncate">
                      {user.display_name || 'No Name'}
                    </span>
                    <span className={`text-[10px] font-[family-name:var(--font-mono)] px-1.5 py-0.5 rounded border ${tierBadgeClass(user.tier)}`}>
                      {user.tier.toUpperCase()}
                    </span>
                    {user.role === 'admin' && (
                      <span className="text-[10px] font-[family-name:var(--font-mono)] px-1.5 py-0.5 rounded border bg-amber/10 text-amber border-amber/30">
                        ADMIN
                      </span>
                    )}
                    {isNew(user.created_at) && (
                      <span className="text-[10px] font-[family-name:var(--font-mono)] px-1.5 py-0.5 rounded border bg-green/10 text-green border-green/30">
                        NEW
                      </span>
                    )}
                    {isSelf && (
                      <span className="text-[10px] font-[family-name:var(--font-mono)] px-1.5 py-0.5 rounded border bg-blue/10 text-blue border-blue/30">
                        YOU
                      </span>
                    )}
                  </div>
                  <div className="text-text-dim text-xs font-[family-name:var(--font-mono)] mt-0.5 truncate">
                    {user.email}
                  </div>
                  <div className="text-text-dim/50 text-[11px] mt-0.5 flex items-center gap-1.5 flex-wrap">
                    <span>{providerLabel(user.provider)}</span>
                    <span>&middot;</span>
                    <span>Joined {new Date(user.created_at).toLocaleDateString()}</span>
                    <span>&middot;</span>
                    <span>Last seen {timeAgo(user.last_sign_in)}</span>
                  </div>
                </div>

                {/* Quick stats (desktop) */}
                <div className="hidden md:flex items-center gap-5 text-center shrink-0">
                  <div>
                    <div className="text-text-bright text-sm font-bold font-[family-name:var(--font-mono)]">{user.chat_count_today}</div>
                    <div className="text-text-dim/50 text-[10px] font-[family-name:var(--font-mono)]">TODAY</div>
                  </div>
                  <div>
                    <div className="text-text-bright text-sm font-bold font-[family-name:var(--font-mono)]">{user.conversations_count}</div>
                    <div className="text-text-dim/50 text-[10px] font-[family-name:var(--font-mono)]">CONVOS</div>
                  </div>
                  <div>
                    <div className="text-text-bright text-sm font-bold font-[family-name:var(--font-mono)]">{user.reports_count}</div>
                    <div className="text-text-dim/50 text-[10px] font-[family-name:var(--font-mono)]">REPORTS</div>
                  </div>
                </div>

                {/* Expand arrow */}
                <svg
                  className={`w-4 h-4 text-text-dim shrink-0 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                  fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                </svg>
              </button>

              {/* Expanded detail panel */}
              {isExpanded && (
                <div className="border-t border-border px-4 py-4 bg-bg2/50">
                  {/* Stats grid */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                    <div className="bg-card border border-border rounded p-3 text-center">
                      <div className="font-[family-name:var(--font-display)] text-xl text-text-bright">{user.conversations_count}</div>
                      <div className="text-text-dim text-[10px] font-[family-name:var(--font-mono)] uppercase">Conversations</div>
                    </div>
                    <div className="bg-card border border-border rounded p-3 text-center">
                      <div className="font-[family-name:var(--font-display)] text-xl text-text-bright">{user.reports_count}</div>
                      <div className="text-text-dim text-[10px] font-[family-name:var(--font-mono)] uppercase">Reports</div>
                    </div>
                    <div className="bg-card border border-border rounded p-3 text-center">
                      <div className="font-[family-name:var(--font-display)] text-xl text-text-bright">
                        {user.tokens_active}<span className="text-text-dim text-sm">/{user.tokens_total}</span>
                      </div>
                      <div className="text-text-dim text-[10px] font-[family-name:var(--font-mono)] uppercase">MCP Tokens</div>
                    </div>
                    <div className="bg-card border border-border rounded p-3 text-center">
                      <div className="font-[family-name:var(--font-display)] text-xl text-text-bright">{user.chat_count_today}</div>
                      <div className="text-text-dim text-[10px] font-[family-name:var(--font-mono)] uppercase">Chats Today</div>
                    </div>
                  </div>

                  {/* Configuration */}
                  <div className="bg-card border border-border rounded p-4 mb-4">
                    <div className="text-text-dim text-[10px] font-[family-name:var(--font-mono)] uppercase tracking-wider mb-3">Configuration</div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      <div className="flex items-center gap-2">
                        <span className="text-text-dim text-xs w-16 shrink-0">Model:</span>
                        <span className="font-[family-name:var(--font-mono)] text-text text-xs">{user.preferred_model}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-text-dim text-xs w-16 shrink-0">Stripe:</span>
                        <span className={`font-[family-name:var(--font-mono)] text-xs ${user.stripe_customer_id ? 'text-green' : 'text-text-dim/50'}`}>
                          {user.stripe_customer_id ? 'Connected' : 'Not connected'}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-text-dim text-xs w-16 shrink-0">API Keys:</span>
                        <div className="flex items-center gap-1.5">
                          <span className={`text-[10px] font-[family-name:var(--font-mono)] px-1.5 py-0.5 rounded border ${user.has_openrouter_key ? 'bg-green/10 text-green border-green/30' : 'bg-card2 text-text-dim/30 border-border'}`}>
                            OR
                          </span>
                          <span className={`text-[10px] font-[family-name:var(--font-mono)] px-1.5 py-0.5 rounded border ${user.has_claude_key ? 'bg-green/10 text-green border-green/30' : 'bg-card2 text-text-dim/30 border-border'}`}>
                            CL
                          </span>
                          <span className={`text-[10px] font-[family-name:var(--font-mono)] px-1.5 py-0.5 rounded border ${user.has_openai_key ? 'bg-green/10 text-green border-green/30' : 'bg-card2 text-text-dim/30 border-border'}`}>
                            OA
                          </span>
                        </div>
                      </div>
                      <div>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-text-dim text-xs">OpenRouter:</span>
                          <span className="font-[family-name:var(--font-mono)] text-xs text-text">
                            ${user.openrouter_usage_usd.toFixed(2)} / ${user.openrouter_usage_limit_usd.toFixed(2)}
                          </span>
                        </div>
                        <div className="w-full h-1.5 bg-card2 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all ${usagePct > 80 ? 'bg-red' : usagePct > 50 ? 'bg-amber' : 'bg-green'}`}
                            style={{ width: `${usagePct}%` }}
                          />
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Actions */}
                  {!isSelf ? (
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-text-dim text-[10px] font-[family-name:var(--font-mono)] uppercase tracking-wider mr-1">Actions:</span>
                      {user.tier !== 'pro' && (
                        <button
                          onClick={e => { e.stopPropagation(); handleAction(user.id, 'set_tier', 'pro'); }}
                          disabled={isUpdating}
                          className="text-xs bg-green/10 hover:bg-green/20 text-green border border-green/30 px-2.5 py-1 rounded transition-colors disabled:opacity-50"
                        >
                          Set Pro
                        </button>
                      )}
                      {user.tier !== 'free' && (
                        <button
                          onClick={e => { e.stopPropagation(); handleAction(user.id, 'set_tier', 'free'); }}
                          disabled={isUpdating}
                          className="text-xs bg-blue/10 hover:bg-blue/20 text-blue border border-blue/30 px-2.5 py-1 rounded transition-colors disabled:opacity-50"
                        >
                          Set Free
                        </button>
                      )}
                      {user.tier !== 'blocked' && (
                        <button
                          onClick={e => { e.stopPropagation(); handleAction(user.id, 'set_tier', 'blocked'); }}
                          disabled={isUpdating}
                          className="text-xs bg-red/10 hover:bg-red/20 text-red border border-red/30 px-2.5 py-1 rounded transition-colors disabled:opacity-50"
                        >
                          Block
                        </button>
                      )}
                      {user.role !== 'admin' && (
                        <button
                          onClick={e => { e.stopPropagation(); handleAction(user.id, 'set_role', 'admin'); }}
                          disabled={isUpdating}
                          className="text-xs bg-amber/10 hover:bg-amber/20 text-amber border border-amber/30 px-2.5 py-1 rounded transition-colors disabled:opacity-50"
                        >
                          Make Admin
                        </button>
                      )}
                      {user.role === 'admin' && (
                        <button
                          onClick={e => { e.stopPropagation(); handleAction(user.id, 'set_role', 'user'); }}
                          disabled={isUpdating}
                          className="text-xs bg-card2 hover:bg-border text-text-dim border border-border px-2.5 py-1 rounded transition-colors disabled:opacity-50"
                        >
                          Remove Admin
                        </button>
                      )}
                      {user.chat_count_today > 0 && (
                        <button
                          onClick={e => { e.stopPropagation(); handleAction(user.id, 'reset_chat_count'); }}
                          disabled={isUpdating}
                          className="text-xs bg-card2 hover:bg-border text-text-dim border border-border px-2.5 py-1 rounded transition-colors disabled:opacity-50"
                        >
                          Reset Chats
                        </button>
                      )}
                      {isUpdating && (
                        <span className="text-text-dim text-xs animate-pulse font-[family-name:var(--font-mono)]">Updating...</span>
                      )}
                    </div>
                  ) : (
                    <div className="text-text-dim/50 text-xs font-[family-name:var(--font-mono)]">
                      This is your account &mdash; use the Supabase SQL editor for self-changes.
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}

        {filtered.length === 0 && (
          <div className="text-center py-12 text-text-dim text-sm">
            No users match your search.
          </div>
        )}
      </div>
    </div>
  );
}
