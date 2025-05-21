
import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { supabase } from '../integrations/supabase/client';
import { toast } from 'sonner';
import { Terminal, Shield, LogIn } from 'lucide-react';

const Login = () => {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!email || !password) {
      toast.error('Please enter both email and password');
      return;
    }
    
    try {
      setLoading(true);
      const { data, error } = await supabase.auth.signInWithPassword({ 
        email, 
        password 
      });
      
      if (error) throw error;
      
      toast.success('Login successful');
      
      // Check if profile exists
      const { data: profile } = await supabase
        .from('profiles')
        .select('username')
        .eq('id', data.user.id)
        .single();
        
      // Route based on profile completion
      if (profile && profile.username) {
        navigate('/dashboard');
      } else {
        navigate('/profile-setup');
      }
      
    } catch (error: any) {
      toast.error(error.message || 'An error occurred during login');
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-black matrix-bg">
      <div className="absolute inset-0 opacity-10 pointer-events-none">
        <div className="matrix-rain"></div>
      </div>
      
      <div className="w-full max-w-md px-4">
        <div className="text-center mb-6">
          <div className="flex justify-center mb-4">
            <Shield className="h-12 w-12 text-green-500 animate-pulse-glow" />
          </div>
          <h1 className="text-3xl font-bold font-mono text-green-400 hacker-text mb-1">CYBERSENTRY</h1>
          <p className="text-green-500/60 text-sm font-mono">SECURE NETWORK PROTOCOL</p>
        </div>
        
        <Card className="border border-green-500/30 bg-black/80 terminal-window">
          <div className="terminal-header">
            <div className="terminal-circle bg-red-500/70"></div>
            <div className="terminal-circle bg-yellow-500/70"></div>
            <div className="terminal-circle bg-green-500/70"></div>
            <div className="ml-2 text-sm text-green-400/80 font-mono">login.sh</div>
          </div>
          
          <div className="p-6">
            <h2 className="text-xl font-bold text-green-400 font-mono flex items-center gap-2 mb-5">
              <Terminal className="h-5 w-5" />
              <span>SYSTEM ACCESS</span>
            </h2>
            
            <form onSubmit={handleLogin} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email" className="text-green-400 font-mono">USER ID</Label>
                <div className="relative">
                  <Input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="user@domain.com"
                    className="bg-black/60 border-green-500/30 text-green-400 font-mono cyber-input focus:border-green-400"
                    autoComplete="email"
                  />
                  <div className="absolute right-2 top-2.5 h-1 w-1 rounded-full bg-green-500 animate-pulse"></div>
                </div>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="password" className="text-green-400 font-mono">ACCESS KEY</Label>
                <div className="relative">
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="bg-black/60 border-green-500/30 text-green-400 font-mono cyber-input focus:border-green-400"
                    autoComplete="current-password"
                  />
                  <div className="absolute right-2 top-2.5 h-1 w-1 rounded-full bg-green-500 animate-pulse"></div>
                </div>
              </div>
              
              <Button 
                type="submit" 
                disabled={loading}
                className="w-full cyber-button bg-green-600 hover:bg-green-700 text-black font-bold font-mono"
              >
                {loading ? (
                  <>
                    <div className="h-4 w-4 border-2 border-t-transparent border-black rounded-full animate-spin mr-2"></div>
                    <span>AUTHENTICATING...</span>
                  </>
                ) : (
                  <>
                    <LogIn className="mr-2 h-4 w-4" />
                    <span>CONNECT</span>
                  </>
                )}
              </Button>
            </form>
            
            <div className="mt-6 text-center">
              <p className="text-green-500/60 text-sm font-mono">
                NO ACCESS CREDENTIALS?
              </p>
              <Link 
                to="/register" 
                className="inline-block mt-1 text-green-400 hover:text-green-300 font-mono"
              >
                CREATE_NEW_ACCESS()
              </Link>
            </div>
            
            <div className="mt-8 text-xs text-green-500/50 font-mono">
              <div className="mb-2">&gt; Connection encrypted with AES-256</div>
              <div>&gt; System v2.1.0 | Last updated: 2025-05-21</div>
            </div>
          </div>
        </Card>
      </div>
      
      {/* Code-like animation at the bottom */}
      <div className="fixed bottom-0 left-0 right-0 h-16 overflow-hidden pointer-events-none">
        <div className="text-green-500/30 text-xs font-mono whitespace-nowrap animate-scroll">
          {Array(100).fill(0).map((_, i) => (
            <span key={i} className="mr-4">
              {Math.random().toString(36).substring(2, 10)}_{Math.random().toString(16).substring(2, 6)}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Login;
