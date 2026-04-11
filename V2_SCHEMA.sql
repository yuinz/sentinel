-- ============================================================
-- Sentinel V2 User Policies Schema
-- Run this once in your Supabase SQL Editor.
-- One row per user. No dependency on any existing table.
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

-- RLS intentionally disabled.
-- Auth is enforced server-side via Supabase JWT verification in Express.
-- The server uses the service role key which bypasses RLS anyway.
ALTER TABLE public.user_policies DISABLE ROW LEVEL SECURITY;
