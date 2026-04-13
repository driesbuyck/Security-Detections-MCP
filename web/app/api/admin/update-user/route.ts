import { NextRequest } from 'next/server';
import { createClient, createServiceClient } from '@/lib/supabase/server';

export async function POST(request: NextRequest) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const service = await createServiceClient();
  const { data: profile } = await service
    .from('profiles')
    .select('role')
    .eq('id', user.id)
    .single();

  if (profile?.role !== 'admin') {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }

  const body = await request.json();
  const { userId, action, value } = body;

  if (!userId || !action) {
    return Response.json({ error: 'Missing userId or action' }, { status: 400 });
  }

  // Prevent self-demotion
  if (userId === user.id && (action === 'set_tier' || action === 'set_role')) {
    return Response.json({ error: 'Cannot change your own tier or role from here' }, { status: 400 });
  }

  try {
    switch (action) {
      case 'set_tier': {
        const validTiers = ['free', 'pro', 'blocked'];
        if (!validTiers.includes(value)) {
          return Response.json({ error: 'Invalid tier' }, { status: 400 });
        }
        const { error } = await service.from('profiles').update({ tier: value }).eq('id', userId);
        if (error) throw error;
        break;
      }
      case 'set_role': {
        const validRoles = ['user', 'admin'];
        if (!validRoles.includes(value)) {
          return Response.json({ error: 'Invalid role' }, { status: 400 });
        }
        const { error } = await service.from('profiles').update({ role: value }).eq('id', userId);
        if (error) throw error;
        break;
      }
      case 'reset_chat_count': {
        const { error } = await service.from('profiles').update({ chat_count_today: 0 }).eq('id', userId);
        if (error) throw error;
        break;
      }
      default:
        return Response.json({ error: 'Unknown action' }, { status: 400 });
    }
    return Response.json({ success: true });
  } catch (err) {
    console.error('Admin action failed:', err);
    return Response.json({ error: 'Internal error' }, { status: 500 });
  }
}
