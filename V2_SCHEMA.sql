-- ============================================================
-- Sentinel V2 Tenant Policies Schema
-- Run this once in your Supabase SQL Editor.
-- Does NOT affect V1 tables (api_access, telemetry) in any way.
-- ============================================================

CREATE TABLE IF NOT EXISTS public.tenant_policies (
    api_key          TEXT PRIMARY KEY REFERENCES public.api_access(api_key) ON DELETE CASCADE,
    user_id          UUID NOT NULL,
    mode             TEXT    DEFAULT 'BALANCED',
    difficulty_level INTEGER DEFAULT 3,
    block_proxies    BOOLEAN DEFAULT true,
    block_datacenters BOOLEAN DEFAULT false,
    force_bwt        BOOLEAN DEFAULT true,
    allowed_asns     TEXT[]  DEFAULT '{}',
    blocked_asns     TEXT[]  DEFAULT '{}',
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at       TIMESTAMPTZ DEFAULT NOW()
);

-- Row Level Security — users only ever see/edit their own rows
ALTER TABLE public.tenant_policies ENABLE ROW LEVEL SECURITY;

CREATE POLICY "select_own_policy" ON public.tenant_policies
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "insert_own_policy" ON public.tenant_policies
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "update_own_policy" ON public.tenant_policies
    FOR UPDATE USING (auth.uid() = user_id);
