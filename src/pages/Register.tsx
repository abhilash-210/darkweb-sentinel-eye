
import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, AlertTriangle, UserPlus } from 'lucide-react';
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
      toast.error('Passwords do not match');
      return;
    }
    
    if (!acceptTerms) {
      toast.error('Please accept the terms and conditions');
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

      toast.success('Registration successful! Please check your email for verification.');
      navigate('/login');
    } catch (error: any) {
      toast.error(`Registration failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-black p-4">
      <div className="absolute inset-0 network-lines opacity-20"></div>
      
      <div className="cyber-card w-full max-w-md p-8 z-10">
        <div className="flex justify-center mb-6">
          <Shield className="h-12 w-12 text-green-500 animate-pulse-glow" />
        </div>
        
        <h1 className="text-3xl font-bold text-center mb-2 text-white">
          Create <span className="text-green-500">Account</span>
        </h1>
        <p className="text-gray-400 text-center mb-8">
          Join CyberSentry to protect against online threats
        </p>
        
        <form onSubmit={handleRegister} className="space-y-6">
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
            <label htmlFor="password" className="text-sm font-medium text-gray-300 block">
              Password
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
            <p className="text-xs text-gray-500">
              Password must be at least 8 characters with numbers and special characters
            </p>
          </div>
          
          <div className="space-y-2">
            <label htmlFor="confirmPassword" className="text-sm font-medium text-gray-300 block">
              Confirm Password
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
          
          <div className="flex items-start space-x-3">
            <Checkbox 
              id="terms" 
              checked={acceptTerms}
              onCheckedChange={() => setAcceptTerms(!acceptTerms)}
              className="mt-1 bg-black border-green-500/50 data-[state=checked]:bg-green-500 data-[state=checked]:text-black"
            />
            <label htmlFor="terms" className="text-sm text-gray-400">
              I accept the <a href="#" className="text-green-500 hover:text-green-400">Terms of Service</a> and <a href="#" className="text-green-500 hover:text-green-400">Privacy Policy</a>
            </label>
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
                  <UserPlus className="h-5 w-5" />
                  <span>Create Account</span>
                </>
              )}
            </Button>
          </div>
        </form>
        
        <div className="mt-8 text-center">
          <div className="text-sm text-gray-400">
            Already have an account?{' '}
            <Link to="/login" className="text-green-500 hover:text-green-400">
              Sign in
            </Link>
          </div>
        </div>
        
        <div className="mt-6 p-4 bg-black/80 rounded border border-green-500/10 flex items-center gap-3">
          <AlertTriangle className="h-5 w-5 text-yellow-500 flex-shrink-0" />
          <p className="text-xs text-gray-400">
            Your data is encrypted and protected using industry-standard security protocols.
          </p>
        </div>
      </div>
      
      <div className="mt-8 text-gray-500 text-xs">
        © {new Date().getFullYear()} CyberSentry | Secure URL Analysis Tool
      </div>
    </div>
  );
};

export default Register;
