
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
        throw error;
      }

      toast.success('Login successful! Redirecting to dashboard...');
      navigate('/dashboard');
    } catch (error: any) {
      toast.error(`Login failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-cyber-dark p-4">
      <div className="absolute inset-0 network-lines opacity-20"></div>
      
      <div className="cyber-card w-full max-w-md p-8 z-10">
        <div className="flex justify-center mb-6">
          <Shield className="h-12 w-12 text-cyber-accent animate-pulse-glow" />
        </div>
        
        <h1 className="text-3xl font-bold text-center mb-2 text-white">
          Secure <span className="text-cyber-accent">Login</span>
        </h1>
        <p className="text-gray-400 text-center mb-8">
          Access your PhishGuard dashboard
        </p>
        
        <form onSubmit={handleLogin} className="space-y-6">
          <div className="space-y-2">
            <label htmlFor="email" className="text-sm font-medium text-gray-300 block">
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
              <label htmlFor="password" className="text-sm font-medium text-gray-300">
                Password
              </label>
              <a href="#" className="text-sm text-cyber-accent hover:text-cyber-purple">
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
          <div className="text-sm text-gray-400">
            Don't have an account?{' '}
            <Link to="/register" className="text-cyber-accent hover:text-cyber-purple">
              Create an account
            </Link>
          </div>
        </div>
        
        <div className="mt-6 p-4 bg-cyber-dark/80 rounded border border-cyber-accent/10 flex items-center gap-3">
          <AlertTriangle className="h-5 w-5 text-cyber-warning flex-shrink-0" />
          <p className="text-xs text-gray-400">
            Always ensure you're on the official PhishGuard domain before entering credentials.
          </p>
        </div>
      </div>
      
      <div className="mt-8 text-gray-500 text-xs">
        © {new Date().getFullYear()} PhishGuard | Secure Link Analysis Tool
      </div>
    </div>
  );
};

export default Login;
