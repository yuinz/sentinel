-- ============================================================
-- Sentinel V2 User Policies Schema
-- Run this once in your Supabase SQL Editor.
-- One row per user. No dependency on api_access table.
-- Does NOT affect V1 tables (api_access, telemetry) in any way.
-- ============================================================

CREATE TABLE IF NOT EXISTS public.user_policies (
    user_id          UUID PRIMARY KEY,
    mode             TEXT    DEFAULT 'BALANCED',
    difficulty_level INTEGER DEFAULT 3,
    block_proxies    BOOLEAN DEFAULT true,
    block_datacenters BOOLEAN DEFAULT false,
    force_bwt        BOOLEAN DEFAULT true,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at       TIMESTAMPTZ DEFAULT NOW()
);

-- Row Level Security
ALTER TABLE public.user_policies ENABLE ROW LEVEL SECURITY;

CREATE POLICY "select_own_policy" ON public.user_policies
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "insert_own_policy" ON public.user_policies
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "update_own_policy" ON public.user_policies
    FOR UPDATE USING (auth.uid() = user_id);
