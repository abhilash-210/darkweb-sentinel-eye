
import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, AlertTriangle, LogIn } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { supabase } from "@/integrations/supabase/client";

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    // Check if user is already logged in
    const checkSession = async () => {
      const { data: { session } } = await supabase.auth.getSession();
      if (session) {
        navigate('/dashboard');
      }
    };
    
    checkSession();
  }, [navigate]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    
    setLoading(true);
    
    try {
      const { data, error } = await supabase.auth.signInWithPassword({
        email,
        password,
      });

      if (error) {
        // Check for email confirmation error
        if (error.message.includes('Email not confirmed')) {
          toast.error('Please verify your email before logging in. Check your inbox for a confirmation link.');
        } else {
          throw error;
        }
      } else {
        toast.success('Login successful! Redirecting to dashboard...');
        navigate('/dashboard');
      }
    } catch (error: any) {
      toast.error(`Login failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-slate-50 p-4">
      <div className="bg-white w-full max-w-md p-8 z-10 rounded-lg shadow-sm border border-gray-100">
        <div className="flex justify-center mb-6">
          <Shield className="h-12 w-12 text-teal-500 animate-pulse-glow" />
        </div>
        
        <h1 className="text-3xl font-bold text-center mb-2 text-gray-800">
          Secure <span className="text-teal-600">Login</span>
        </h1>
        <p className="text-gray-600 text-center mb-8">
          Access your CyberSentry dashboard
        </p>
        
        <form onSubmit={handleLogin} className="space-y-6">
          <div className="space-y-2">
            <label htmlFor="email" className="text-sm font-medium text-gray-700 block">
              Email Address
            </label>
            <Input
              id="email"
              type="email"
              placeholder="name@example.com"
              className="cyber-input w-full"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          
          <div className="space-y-2">
            <div className="flex justify-between">
              <label htmlFor="password" className="text-sm font-medium text-gray-700">
                Password
              </label>
              <a href="#" className="text-sm text-teal-600 hover:text-teal-500">
                Forgot password?
              </a>
            </div>
            <Input
              id="password"
              type="password"
              placeholder="••••••••"
              className="cyber-input w-full"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          
          <div className="pt-2">
            <Button
              disabled={loading}
              type="submit"
              className="cyber-button w-full flex items-center justify-center gap-2"
            >
              {loading ? (
                <div className="h-5 w-5 border-2 border-t-transparent border-white rounded-full animate-spin"></div>
              ) : (
                <>
                  <LogIn className="h-5 w-5" />
                  <span>Sign In</span>
                </>
              )}
            </Button>
          </div>
        </form>
        
        <div className="mt-8 text-center">
          <div className="text-sm text-gray-600">
            Don't have an account?{' '}
            <Link to="/register" className="text-teal-600 hover:text-teal-500">
              Create an account
            </Link>
          </div>
        </div>
        
        <div className="mt-6 p-4 bg-amber-50 rounded border border-amber-100 flex items-center gap-3">
          <AlertTriangle className="h-5 w-5 text-amber-500 flex-shrink-0" />
          <p className="text-xs text-gray-600">
            Always ensure you're on the official CyberSentry domain before entering credentials.
          </p>
        </div>
      </div>
      
      <div className="mt-8 text-gray-500 text-xs">
        © {new Date().getFullYear()} CyberSentry | Secure URL Analysis Tool
      </div>
    </div>
  );
};

export default Login;
