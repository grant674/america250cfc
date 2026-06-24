// ============================================================
// America250 CFC — Judge portal config
// Returns the public Supabase anon key for the /judge/ client.
// The anon key is safe to expose (it's designed for client-side
// use, RLS does the actual gating) but we deliver it via a tiny
// function so it can be rotated in env vars without code edits.
// ============================================================

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

export const handler = async (event) => {
  if (event.httpMethod !== "GET") {
    return { statusCode: 405, body: "method_not_allowed" };
  }
  if (!SUPABASE_ANON_KEY) {
    return {
      statusCode: 500,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "SUPABASE_ANON_KEY not set" }),
    };
  }
  return {
    statusCode: 200,
    headers: {
      "Content-Type": "application/json",
      // Short cache — this rarely changes but should pick up rotations
      // within a few minutes if the key is ever rolled.
      "Cache-Control": "public, max-age=300, must-revalidate",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
    },
    body: JSON.stringify({
      supabase_url: SUPABASE_URL,
      supabase_anon_key: SUPABASE_ANON_KEY,
    }),
  };
};
