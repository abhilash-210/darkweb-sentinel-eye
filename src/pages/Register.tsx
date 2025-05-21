
import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, UserPlus, Terminal, LockKeyhole } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
import { supabase } from "@/integrations/supabase/client";

const Register = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [acceptTerms, setAcceptTerms] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  
  // Typing effect for header
  const [displayText, setDisplayText] = useState('');
  const textToType = 'NEW AGENT REGISTRATION';
  
  useEffect(() => {
    // Type out text effect
    let i = 0;
    const typingInterval = setInterval(() => {
      if (i <= textToType.length) {
        setDisplayText(textToType.substring(0, i));
        i++;
      } else {
        clearInterval(typingInterval);
      }
    }, 100);
    
    return () => clearInterval(typingInterval);
  }, []);

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

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (password !== confirmPassword) {
      toast.error('Security keys do not match');
      return;
    }
    
    if (!acceptTerms) {
      toast.error('You must accept the protocols');
      return;
    }
    
    setLoading(true);
    
    try {
      const { data, error } = await supabase.auth.signUp({
        email,
        password,
      });

      if (error) {
        throw error;
      }

      toast.success('Registration successful. Check your communications channel for verification.');
      navigate('/login');
    } catch (error: any) {
      toast.error(`Registration failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

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
          <div className="ml-3 text-green-400 text-xs">/usr/bin/register</div>
        </div>
        
        <div className="flex justify-center mb-6">
          <Shield className="h-12 w-12 text-green-500 animate-pulse-glow" />
        </div>
        
        <h1 className="text-2xl font-bold text-center mb-2 hacker-text overflow-hidden">
          <span className="inline-block">&gt; </span>
          <span>{displayText}</span>
          <span className="inline-block animate-blink">_</span>
        </h1>
        <p className="text-green-400 text-center mb-8 opacity-80">
          &lt;CREATING_SECURE_IDENTITY/&gt;
        </p>
        
        <form onSubmit={handleRegister} className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="email" className="text-sm font-medium text-green-400 block flex items-center">
              <Terminal className="h-4 w-4 mr-2" />
              <span>COMMS_CHANNEL [email]:</span>
            </label>
            <Input
              id="email"
              type="email"
              placeholder="agent@cybersentry.sec"
              className="cyber-input w-full"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          
          <div className="space-y-2">
            <label htmlFor="password" className="text-sm font-medium text-green-400 flex items-center">
              <LockKeyhole className="h-4 w-4 mr-2" />
              <span>SECURITY_KEY:</span>
            </label>
            <Input
              id="password"
              type="password"
              placeholder="••••••••"
              className="cyber-input w-full"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            <p className="text-xs text-green-500/80">
              [ min_length: 8 | req: numbers + special_chars ]
            </p>
          </div>
          
          <div className="space-y-2">
            <label htmlFor="confirmPassword" className="text-sm font-medium text-green-400 flex items-center">
              <LockKeyhole className="h-4 w-4 mr-2" />
              <span>CONFIRM_KEY:</span>
            </label>
            <Input
              id="confirmPassword"
              type="password"
              placeholder="••••••••"
              className="cyber-input w-full"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
          </div>
          
          <div className="flex items-start space-x-3 pt-2">
            <Checkbox 
              id="terms" 
              checked={acceptTerms}
              onCheckedChange={() => setAcceptTerms(!acceptTerms)}
              className="mt-1 data-[state=checked]:bg-green-500 data-[state=checked]:text-black"
            />
            <label htmlFor="terms" className="text-xs text-green-400">
              I accept the <a href="#" className="text-green-500 underline hover:text-green-400">Security Protocols</a> and <a href="#" className="text-green-500 underline hover:text-green-400">Data Handling Procedures</a>
            </label>
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
                  <UserPlus className="h-5 w-5" />
                  <span>INITIALIZE IDENTITY</span>
                </>
              )}
            </Button>
          </div>
        </form>
        
        <div className="mt-6 text-center">
          <div className="text-sm text-green-400">
            [ existing_agent ] ?{' '}
            <Link to="/login" className="text-green-500 hover:text-green-400">
              ACCESS_SYSTEM
            </Link>
          </div>
        </div>
        
        <div className="mt-5 p-3 bg-green-900/20 rounded border border-green-500/30 text-xs text-green-400 font-mono">
          <p>
            &gt; Connection encrypted using quantum-resistant algorithm.
          </p>
        </div>
      </div>
      
      <div className="mt-8 text-green-500 text-xs opacity-70">
        © {new Date().getFullYear()} CyberSentry | Secure Network Protocol v1.3.7
      </div>
    </div>
  );
};

export default Register;
