
import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card } from '@/components/ui/card';
import { Shield, Terminal, UserPlus } from 'lucide-react';

const Register = () => {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!email || !password || !confirmPassword) {
      toast.error('All fields are required');
      return;
    }
    
    if (password !== confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }
    
    if (password.length < 6) {
      toast.error('Password must be at least 6 characters');
      return;
    }
    
    try {
      setLoading(true);
      const { data, error } = await supabase.auth.signUp({
        email,
        password,
      });
      
      if (error) throw error;
      
      toast.success('Registration successful');
      
      // Navigate to profile setup
      navigate('/profile-setup');
      
    } catch (error: any) {
      toast.error(error.message || 'An error occurred during registration');
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
            <div className="ml-2 text-sm text-green-400/80 font-mono">register.sh</div>
          </div>
          
          <div className="p-6">
            <h2 className="text-xl font-bold text-green-400 font-mono flex items-center gap-2 mb-5">
              <Terminal className="h-5 w-5" />
              <span>CREATE NEW ACCESS</span>
            </h2>
            
            <form onSubmit={handleRegister} className="space-y-4">
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
                    autoComplete="new-password"
                  />
                  <div className="absolute right-2 top-2.5 h-1 w-1 rounded-full bg-green-500 animate-pulse"></div>
                </div>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="confirmPassword" className="text-green-400 font-mono">CONFIRM ACCESS KEY</Label>
                <div className="relative">
                  <Input
                    id="confirmPassword"
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="bg-black/60 border-green-500/30 text-green-400 font-mono cyber-input focus:border-green-400"
                    autoComplete="new-password"
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
                    <span>INITIALIZING...</span>
                  </>
                ) : (
                  <>
                    <UserPlus className="mr-2 h-4 w-4" />
                    <span>REGISTER NEW USER</span>
                  </>
                )}
              </Button>
            </form>
            
            <div className="mt-6 text-center">
              <p className="text-green-500/60 text-sm font-mono">
                EXISTING CREDENTIALS?
              </p>
              <Link 
                to="/login" 
                className="inline-block mt-1 text-green-400 hover:text-green-300 font-mono"
              >
                ACCESS_SYSTEM()
              </Link>
            </div>
            
            <div className="mt-8 text-xs text-green-500/50 font-mono">
              <div className="mb-2">&gt; Registration secured with RSA-4096</div>
              <div>&gt; System v2.1.0 | Last updated: 2025-05-21</div>
            </div>
          </div>
        </Card>
      </div>
      
      {/* Binary-like floating elements */}
      <div className="fixed top-0 left-0 right-0 bottom-0 pointer-events-none overflow-hidden">
        {Array.from({ length: 20 }).map((_, i) => (
          <div 
            key={i}
            className="absolute text-green-500/10 text-xs font-mono"
            style={{
              top: `${Math.random() * 100}%`,
              left: `${Math.random() * 100}%`,
              animation: `matrix-rain ${5 + Math.random() * 15}s linear infinite`,
              animationDelay: `${Math.random() * 5}s`,
            }}
          >
            {Math.random() > 0.5 ? '0' : '1'}
          </div>
        ))}
      </div>
    </div>
  );
};

export default Register;
