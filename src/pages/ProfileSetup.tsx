
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import { Terminal, Shield, UserCheck, LogOut } from 'lucide-react';

const ProfileSetup = () => {
  const navigate = useNavigate();
  const [fullName, setFullName] = useState('');
  const [loading, setLoading] = useState(false);
  const [user, setUser] = useState<any>(null);
  
  useEffect(() => {
    const checkAuth = async () => {
      const { data: { session } } = await supabase.auth.getSession();
      
      if (!session) {
        navigate('/login');
        return;
      }
      
      setUser(session.user);
    };
    
    checkAuth();
  }, [navigate]);
  
  const handleProfileSetup = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!fullName) {
      toast.error('Please enter your full name');
      return;
    }
    
    if (!user) {
      toast.error('You need to be logged in to complete your profile');
      return;
    }
    
    try {
      setLoading(true);
      
      const { error } = await supabase
        .from('profiles')
        .upsert({ 
          id: user.id,
          username: fullName
        });
      
      if (error) throw error;
      
      toast.success('Profile setup complete');
      navigate('/dashboard');
    } catch (error: any) {
      toast.error(error.message || 'An error occurred during profile setup');
    } finally {
      setLoading(false);
    }
  };
  
  const handleLogout = async () => {
    await supabase.auth.signOut();
    navigate('/login');
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
            <div className="ml-2 text-sm text-green-400/80 font-mono">setup.sh</div>
          </div>
          
          <div className="p-6">
            <h2 className="text-xl font-bold text-green-400 font-mono flex items-center gap-2 mb-5">
              <Terminal className="h-5 w-5" />
              <span>OPERATOR CONFIGURATION</span>
            </h2>
            
            <div className="mb-4 p-3 border border-green-500/30 rounded bg-green-900/10">
              <p className="text-green-400 font-mono text-sm">
                <span className="text-green-500">[SYSTEM]:</span> Complete your operator profile to access the CyberSentry network.
              </p>
            </div>
            
            <form onSubmit={handleProfileSetup} className="space-y-6">
              <div className="space-y-2">
                <Label htmlFor="fullName" className="text-green-400 font-mono">OPERATOR NAME</Label>
                <div className="relative">
                  <Input
                    id="fullName"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="Full Name"
                    className="bg-black/60 border-green-500/30 text-green-400 font-mono cyber-input focus:border-green-400"
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
                    <span>PROCESSING...</span>
                  </>
                ) : (
                  <>
                    <UserCheck className="mr-2 h-4 w-4" />
                    <span>COMPLETE SETUP</span>
                  </>
                )}
              </Button>
              
              <div className="text-center">
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleLogout}
                  className="text-green-400 border-green-500/30 hover:bg-green-900/20 font-mono"
                >
                  <LogOut className="mr-2 h-4 w-4" />
                  <span>DISCONNECT</span>
                </Button>
              </div>
            </form>
            
            <div className="mt-6 border-t border-green-500/20 pt-4">
              <div className="text-xs text-green-500/50 font-mono">
                <div className="mb-2">&gt; Profile data encrypted with military-grade encryption</div>
                <div>&gt; System v2.1.0 | Last updated: 2025-05-21</div>
              </div>
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

export default ProfileSetup;
