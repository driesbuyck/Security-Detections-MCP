import { createClient, createServiceClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
import Link from 'next/link';
import { AdminUserList } from './admin-user-list';

export const dynamic = 'force-dynamic';

export default async function AdminPage() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect('/login');

  const { data: profile } = await supabase
    .from('profiles')
    .select('role')
    .eq('id', user.id)
    .single();

  if (profile?.role !== 'admin') {
    return (
      <div className="max-w-2xl mx-auto text-center py-20">
        <div className="text-4xl mb-4">&#128274;</div>
        <h1 className="font-[family-name:var(--font-display)] text-3xl text-text-bright tracking-wider mb-2">
          ACCESS DENIED
        </h1>
        <p className="text-text-dim">This page is restricted to administrators.</p>
        <Link href="/dashboard" className="text-amber hover:text-amber-dim text-sm mt-4 inline-block transition-colors">
          &larr; Back to Dashboard
        </Link>
      </div>
    );
  }

  const service = await createServiceClient();

  // Fetch all data in parallel
  const [
    profilesResult,
    authResult,
    convosResult,
    reportsResult,
    tokensResult,
    messagesResult,
  ] = await Promise.all([
    service.from('profiles').select('*').order('created_at', { ascending: false }),
    service.auth.admin.listUsers(),
    service.from('conversations').select('user_id'),
    service.from('threat_reports').select('user_id, status'),
    service.from('mcp_tokens').select('user_id, revoked_at'),
    service.from('messages').select('*', { count: 'exact', head: true }),
  ]);

  const profiles = profilesResult.data || [];
  const authUsers = authResult.data?.users || [];
  const allConvos = convosResult.data || [];
  const allReports = reportsResult.data || [];
  const allTokens = tokensResult.data || [];
  const totalMessages = messagesResult.count || 0;

  // Per-user aggregates
  const convosByUser: Record<string, number> = {};
  allConvos.forEach(c => {
    convosByUser[c.user_id] = (convosByUser[c.user_id] || 0) + 1;
  });

  const reportsByUser: Record<string, number> = {};
  allReports.forEach(r => {
    reportsByUser[r.user_id] = (reportsByUser[r.user_id] || 0) + 1;
  });

  const tokensByUser: Record<string, { total: number; active: number }> = {};
  allTokens.forEach(t => {
    if (!tokensByUser[t.user_id]) tokensByUser[t.user_id] = { total: 0, active: 0 };
    tokensByUser[t.user_id].total++;
    if (!t.revoked_at) tokensByUser[t.user_id].active++;
  });

  // Merge into rich user objects
  const userList = profiles.map(p => {
    const au = authUsers.find(a => a.id === p.id);
    return {
      id: p.id,
      email: au?.email || 'unknown',
      display_name: p.display_name,
      avatar_url: p.avatar_url,
      tier: p.tier || 'free',
      role: p.role || 'user',
      chat_count_today: p.chat_count_today || 0,
      preferred_model: p.preferred_model || 'auto',
      openrouter_usage_usd: p.openrouter_usage_usd || 0,
      openrouter_usage_limit_usd: p.openrouter_usage_limit_usd || 25,
      has_openrouter_key: !!p.openrouter_api_key_encrypted,
      has_claude_key: !!p.claude_api_key_encrypted,
      has_openai_key: !!p.openai_api_key_encrypted,
      stripe_customer_id: p.stripe_customer_id || null,
      provider: au?.app_metadata?.provider || 'email',
      last_sign_in: au?.last_sign_in_at || null,
      created_at: p.created_at,
      updated_at: p.updated_at,
      conversations_count: convosByUser[p.id] || 0,
      reports_count: reportsByUser[p.id] || 0,
      tokens_total: tokensByUser[p.id]?.total || 0,
      tokens_active: tokensByUser[p.id]?.active || 0,
    };
  });

  const stats = {
    totalUsers: userList.length,
    adminUsers: userList.filter(u => u.role === 'admin').length,
    proUsers: userList.filter(u => u.tier === 'pro').length,
    freeUsers: userList.filter(u => u.tier === 'free').length,
    blockedUsers: userList.filter(u => u.tier === 'blocked').length,
    totalConversations: allConvos.length,
    totalMessages,
    totalReports: allReports.length,
    totalTokens: allTokens.length,
    activeTokens: allTokens.filter(t => !t.revoked_at).length,
  };

  return (
    <div className="max-w-5xl mx-auto animate-slide-up">
      <Link href="/account" className="text-text-dim hover:text-text text-sm font-[family-name:var(--font-mono)] mb-4 inline-block transition-colors">
        &larr; Account
      </Link>

      <h1 className="font-[family-name:var(--font-display)] text-4xl text-text-bright tracking-wider mb-2">
        ADMIN PANEL
      </h1>
      <p className="text-text-dim text-sm mb-8">
        Platform overview and user management.
      </p>

      {/* Users breakdown */}
      <div className="mb-6">
        <h2 className="font-[family-name:var(--font-display)] text-lg text-text-bright tracking-wider mb-3">
          USERS
        </h2>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
            <div className="font-[family-name:var(--font-display)] text-3xl text-text-bright">{stats.totalUsers}</div>
            <div className="text-text-dim text-[10px] font-[family-name:var(--font-mono)] uppercase mt-1">Total</div>
          </div>
          <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
            <div className="font-[family-name:var(--font-display)] text-3xl text-amber">{stats.adminUsers}</div>
            <div className="text-text-dim text-[10px] font-[family-name:var(--font-mono)] uppercase mt-1">Admins</div>
          </div>
          <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
            <div className="font-[family-name:var(--font-display)] text-3xl text-green">{stats.proUsers}</div>
            <div className="text-text-dim text-[10px] font-[family-name:var(--font-mono)] uppercase mt-1">Pro</div>
          </div>
          <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
            <div className="font-[family-name:var(--font-display)] text-3xl text-blue">{stats.freeUsers}</div>
            <div className="text-text-dim text-[10px] font-[family-name:var(--font-mono)] uppercase mt-1">Free</div>
          </div>
          <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
            <div className="font-[family-name:var(--font-display)] text-3xl text-red">{stats.blockedUsers}</div>
            <div className="text-text-dim text-[10px] font-[family-name:var(--font-mono)] uppercase mt-1">Blocked</div>
          </div>
        </div>
      </div>

      {/* Platform activity */}
      <div className="mb-8">
        <h2 className="font-[family-name:var(--font-display)] text-lg text-text-bright tracking-wider mb-3">
          PLATFORM ACTIVITY
        </h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
            <div className="font-[family-name:var(--font-display)] text-3xl text-text-bright">{stats.totalConversations}</div>
            <div className="text-text-dim text-[10px] font-[family-name:var(--font-mono)] uppercase mt-1">Conversations</div>
          </div>
          <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
            <div className="font-[family-name:var(--font-display)] text-3xl text-text-bright">{stats.totalMessages.toLocaleString()}</div>
            <div className="text-text-dim text-[10px] font-[family-name:var(--font-mono)] uppercase mt-1">Messages</div>
          </div>
          <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
            <div className="font-[family-name:var(--font-display)] text-3xl text-text-bright">{stats.totalReports}</div>
            <div className="text-text-dim text-[10px] font-[family-name:var(--font-mono)] uppercase mt-1">Reports</div>
          </div>
          <div className="bg-card border border-border rounded-[var(--radius-card)] p-4 text-center">
            <div className="font-[family-name:var(--font-display)] text-3xl text-text-bright">
              {stats.activeTokens}<span className="text-lg text-text-dim">/{stats.totalTokens}</span>
            </div>
            <div className="text-text-dim text-[10px] font-[family-name:var(--font-mono)] uppercase mt-1">MCP Tokens</div>
          </div>
        </div>
      </div>

      {/* User management */}
      <h2 className="font-[family-name:var(--font-display)] text-lg text-text-bright tracking-wider mb-3">
        USER MANAGEMENT
      </h2>
      <AdminUserList users={userList} currentUserId={user.id} />
    </div>
  );
}
