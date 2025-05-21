
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { User, Shield, Check } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { supabase } from "@/integrations/supabase/client";

const ProfileSetup = () => {
  const [fullName, setFullName] = useState('');
  const [loading, setLoading] = useState(false);
  const [user, setUser] = useState<any>(null);
  const navigate = useNavigate();

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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!fullName.trim()) {
      toast.error('Please enter your full name');
      return;
    }
    
    setLoading(true);
    
    try {
      // Update user profile in Supabase
      const { error } = await supabase
        .from('profiles')
        .upsert({ 
          id: user.id,
          full_name: fullName,
          updated_at: new Date().toISOString(),
        });

      if (error) throw error;
      
      toast.success('Identity verified. Welcome to CyberSentry.');
      navigate('/dashboard');
    } catch (error: any) {
      toast.error(`Profile update failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  // Typing animation effect
  const [typedText, setTypedText] = useState('');
  const fullText = 'VERIFY YOUR IDENTITY';
  
  useEffect(() => {
    let i = 0;
    const typingInterval = setInterval(() => {
      if (i <= fullText.length) {
        setTypedText(fullText.substring(0, i));
        i++;
      } else {
        clearInterval(typingInterval);
      }
    }, 100);
    
    return () => clearInterval(typingInterval);
  }, []);

  // Matrix code rain effect
  const generateMatrixChars = () => {
    return Array.from({ length: 20 }, (_, i) => {
      const randomChar = String.fromCharCode(Math.floor(Math.random() * 26) + 65);
      const delay = Math.random() * 5;
      const duration = 2 + Math.random() * 3;
      
      return (
        <div 
          key={i}
          className="absolute text-green-500 opacity-50 animate-matrix-rain"
          style={{
            left: `${Math.random() * 100}%`,
            top: `${Math.random() * 20}%`,
            animationDelay: `${delay}s`,
            animationDuration: `${duration}s`,
            fontSize: `${Math.random() * 10 + 10}px`
          }}
        >
          {randomChar}
        </div>
      );
    });
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen matrix-bg p-4 relative overflow-hidden">
      {/* Matrix code effect in background */}
      <div className="absolute inset-0 opacity-50 pointer-events-none">
        {generateMatrixChars()}
      </div>
      
      <div className="bg-black/80 w-full max-w-md p-8 z-10 rounded-lg shadow-lg border border-green-500/30 terminal-window">
        <div className="terminal-header mb-4">
          <div className="terminal-circle bg-red-500/70"></div>
          <div className="terminal-circle bg-yellow-500/70"></div>
          <div className="terminal-circle bg-green-500/70"></div>
          <div className="ml-3 text-green-400 text-xs">/usr/bin/identity_verification</div>
        </div>
        
        <div className="flex justify-center mb-6">
          <Shield className="h-12 w-12 text-green-500 animate-pulse-glow" />
        </div>
        
        <h1 className="text-2xl font-bold text-center mb-4 hacker-text">
          <span>&gt; </span>
          <span>{typedText}</span>
          <span className="inline-block animate-blink">_</span>
        </h1>
        
        <div className="text-green-400 text-center mb-8 text-sm border-b border-green-500/30 pb-4">
          <p>Before proceeding, we need to verify your identity.</p>
          <p className="mt-2 text-green-300">Please provide your full name.</p>
        </div>
        
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="space-y-2">
            <label htmlFor="fullName" className="text-sm font-medium text-green-400 block flex items-center">
              <User className="h-4 w-4 mr-2" />
              <span>AGENT_IDENTITY [full_name]:</span>
            </label>
            <Input
              id="fullName"
              type="text"
              placeholder="Enter your full name"
              className="cyber-input w-full"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              required
            />
          </div>
          
          <div className="pt-4">
            <Button
              disabled={loading}
              type="submit"
              className="cyber-button w-full flex items-center justify-center gap-2"
            >
              {loading ? (
                <div className="h-5 w-5 border-2 border-t-transparent border-black rounded-full animate-spin"></div>
              ) : (
                <>
                  <Check className="h-5 w-5" />
                  <span>CONFIRM IDENTITY</span>
                </>
              )}
            </Button>
          </div>
        </form>
        
        <div className="mt-6 p-4 bg-green-900/20 rounded border border-green-500/30 text-xs text-green-400">
          <p className="font-mono">
            &gt; All information is encrypted using AES-256 protocol.
          </p>
          <p className="font-mono mt-1">
            &gt; Your identity will be verified through our secure network.
          </p>
        </div>
      </div>
    </div>
  );
};

export default ProfileSetup;
