// This file is automatically generated. Do not edit it directly.
import { createClient } from '@supabase/supabase-js';
import type { Database } from './types';

const SUPABASE_URL = "https://rzqnvhnjlpjdjhajtytw.supabase.co";
const SUPABASE_PUBLISHABLE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJ6cW52aG5qbHBqZGpoYWp0eXR3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDc3MjAyMzIsImV4cCI6MjA2MzI5NjIzMn0.PSzdyMrAVBopOturmmFQYYZCgyf_kMp6Qj1ziUxYKKc";

// Import the supabase client like this:
// import { supabase } from "@/integrations/supabase/client";

export const supabase = createClient<Database>(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY);