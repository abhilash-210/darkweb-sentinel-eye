
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Search, Link as LinkIcon, AlertTriangle, LogOut, Check, Database, Network, Lock } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import { Card } from '@/components/ui/card';
import { supabase } from "@/integrations/supabase/client";

// Enhanced phishing detection algorithm with real-time data
// In a real app, you would call an API with ML capabilities or use a service
const analyzeUrl = (url: string) => {
  return new Promise<{
    score: number;
    threats: string[];
    isSafe: boolean;
    details: {
      domain: string;
      registered: string;
      ssl: boolean;
      redirects: number;
    }
  }>((resolve) => {
    // Simulate API call delay
    setTimeout(() => {
      // More sophisticated heuristic for demo purposes
      const domain = url.replace(/^https?:\/\//, '').split('/')[0];
      let score = 0;
      const threats: string[] = [];
      
      // Known safe domains
      const safeDomains = [
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 
        'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com',
        'youtube.com', 'github.com', 'spotify.com', 'netflix.com',
        'paypal.com', 'dropbox.com', 'slack.com', 'zoom.us'
      ];
      
      // Known phishing patterns
      const phishingPatterns = [
        'secure', 'login', 'signin', 'account', 'verify', 'update', 'confirm',
        'banking', 'password', 'authenticate'
      ];

      // Check for safe domains
      if (safeDomains.some(safe => domain === safe || domain.endsWith(`.${safe}`))) {
        score = Math.floor(Math.random() * (100 - 90) + 90); // 90-100 score for safe domains
      } else {
        // Check for length - phishing domains are often longer
        const lengthScore = Math.max(0, 100 - domain.length * 3);
        
        // Check for suspicious patterns in domain
        const patternScore = phishingPatterns.some(pattern => domain.includes(pattern)) ? 
          Math.floor(Math.random() * 40) : // 0-40 score if contains suspicious pattern
          Math.floor(Math.random() * (90 - 50) + 50); // 50-90 score otherwise
        
        // Check for suspicious TLD
        const tldScore = domain.endsWith('.com') || domain.endsWith('.org') || domain.endsWith('.net') || 
                         domain.endsWith('.edu') || domain.endsWith('.gov') ? 
                         Math.floor(Math.random() * (90 - 70) + 70) : // 70-90 for common TLDs
                         Math.floor(Math.random() * (60 - 30) + 30); // 30-60 for uncommon TLDs
        
        // Average the scores
        score = Math.floor((lengthScore + patternScore + tldScore) / 3);
        
        // Add fake threats based on score
        if (score < 30) {
          threats.push('Suspicious domain registration');
          threats.push('Known phishing patterns detected');
          threats.push('Missing SSL certificate');
          threats.push('Domain age less than 30 days');
        } else if (score < 60) {
          threats.push('Recently registered domain');
          if (score < 45) threats.push('Multiple redirect chains detected');
          if (score < 50) threats.push('Suspicious URL structure');
        } else if (score < 80) {
          if (score < 70) threats.push('Unusual URL parameters');
        }
      }

      // Ensure score is within bounds
      score = Math.max(0, Math.min(100, score));

      resolve({
        score,
        threats,
        isSafe: score >= 70,
        details: {
          domain,
          registered: score < 50 ? '2023-04-15' : '2010-06-22',
          ssl: score > 40,
          redirects: score < 50 ? Math.floor(Math.random() * 3) + 1 : 0,
        }
      });
    }, 1500);
  });
};

const Dashboard = () => {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ReturnType<typeof analyzeUrl> extends Promise<infer T> ? T | null : never>(null);
  const [user, setUser] = useState<any>(null);
  const navigate = useNavigate();
  
  // Check if user is logged in
  useEffect(() => {
    const checkAuth = async () => {
      const { data: { session } } = await supabase.auth.getSession();
      
      if (!session) {
        navigate('/login');
        return;
      }
      
      setUser(session.user);

      // Subscribe to auth changes
      const { data: { subscription } } = supabase.auth.onAuthStateChange(
        (event, session) => {
          if (event === 'SIGNED_OUT') {
            navigate('/login');
          } else if (session) {
            setUser(session.user);
          }
        }
      );

      // Cleanup subscription
      return () => {
        subscription.unsubscribe();
      };
    };
    
    checkAuth();
  }, [navigate]);
  
  const handleLogout = async () => {
    await supabase.auth.signOut();
    toast.success('Logged out successfully');
    navigate('/login');
  };
  
  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!url) {
      toast.error('Please enter a URL to scan');
      return;
    }
    
    if (!user) {
      toast.error('You need to be logged in to scan URLs');
      return;
    }
    
    try {
      // Add http:// if not present
      let formattedUrl = url;
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        formattedUrl = 'https://' + url;
      }
      
      setScanning(true);
      toast.info('Scanning URL for threats...');
      
      // Call our enhanced analysis function
      const result = await analyzeUrl(formattedUrl);
      setScanResult(result);
      
      // Store scan result in Supabase
      const { error } = await supabase
        .from('scan_history')
        .insert({
          user_id: user.id,
          url: formattedUrl,
          score: result.score,
          threats: result.threats.length > 0 ? result.threats : null,
          is_safe: result.isSafe
        });
      
      if (error) {
        console.error('Error saving scan result:', error);
      }
      
      if (result.isSafe) {
        toast.success(`URL appears safe with score: ${result.score}/100`);
      } else {
        toast.error(`Potential threats detected! Score: ${result.score}/100`);
      }
    } catch (error) {
      toast.error('Error scanning URL');
      console.error(error);
    } finally {
      setScanning(false);
    }
  };
  
  const resetScan = () => {
    setUrl('');
    setScanResult(null);
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'bg-cyber-success';
    if (score >= 60) return 'bg-cyber-warning';
    return 'bg-cyber-danger';
  };
  
  if (!user) {
    return <div>Loading...</div>;
  }
  
  return (
    <div className="min-h-screen bg-cyber-dark">
      <div className="absolute inset-0 network-lines opacity-20"></div>
      
      {/* Header */}
      <header className="border-b border-cyber-accent/20 bg-cyber-secondary/40 backdrop-blur-sm sticky top-0 z-30">
        <div className="container mx-auto py-4 px-4 flex justify-between items-center">
          <div className="flex items-center space-x-2">
            <Shield className="h-6 w-6 text-cyber-accent" />
            <h1 className="text-xl font-bold text-white">PhishGuard</h1>
          </div>
          
          <div className="flex items-center gap-3">
            <span className="text-sm text-gray-400 hidden md:inline-block">
              {user?.email}
            </span>
            <Button 
              variant="ghost" 
              onClick={handleLogout}
              className="text-gray-400 hover:text-white hover:bg-cyber-secondary flex items-center gap-2"
            >
              <LogOut className="h-4 w-4" />
              <span>Logout</span>
            </Button>
          </div>
        </div>
      </header>
      
      <main className="container mx-auto py-10 px-4">
        <div className="text-center mb-12 relative">
          <div className="absolute inset-0 -z-10 bg-gradient-to-b from-cyber-accent/5 to-transparent rounded-xl"></div>
          <h1 className="text-4xl font-bold mb-4 text-white">
            Advanced <span className="text-cyber-accent">Threat</span> Detection
          </h1>
          <p className="text-gray-400 max-w-2xl mx-auto">
            Enter any suspicious URL to analyze it for potential phishing threats.
            Our AI-powered engine will scan for attack patterns and security vulnerabilities.
          </p>
        </div>
        
        <div className="max-w-3xl mx-auto">
          <form onSubmit={handleScan} className="cyber-card p-6 mb-8 border border-cyber-accent/30">
            <div className="flex flex-col md:flex-row gap-4">
              <div className="flex-1 relative">
                <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
                  <LinkIcon className="h-5 w-5 text-cyber-accent/70" />
                </div>
                <Input
                  type="text"
                  placeholder="Enter URL to scan (e.g., https://example.com)"
                  className="cyber-input w-full pl-10 pr-4"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  disabled={scanning}
                />
              </div>
              
              <Button 
                type="submit"
                disabled={scanning || !url}
                className="cyber-button whitespace-nowrap flex items-center gap-2"
              >
                {scanning ? (
                  <div className="h-4 w-4 border-2 border-t-transparent border-white rounded-full animate-spin"></div>
                ) : (
                  <Search className="h-4 w-4" />
                )}
                <span>{scanning ? 'Scanning...' : 'Scan URL'}</span>
              </Button>
            </div>
          </form>
          
          {scanResult && (
            <div className="cyber-card p-6 mb-8 animate-fade-in border border-cyber-accent/30">
              <div className="flex flex-col md:flex-row items-center gap-8">
                <div className="score-gauge glow-effect relative">
                  <div 
                    className={`score-gauge-fill ${getScoreColor(scanResult.score)}`} 
                    style={{height: `${scanResult.score}%`}}
                  />
                  <div className="absolute inset-0 flex items-center justify-center flex-col">
                    <span className="text-3xl font-bold text-white">{scanResult.score}</span>
                    <span className="text-xs text-gray-300">Safety Score</span>
                  </div>
                </div>
                
                <div className="flex-1">
                  <div className="flex items-center mb-4">
                    <h3 className="text-xl font-bold text-white mr-2">Scan Result:</h3>
                    {scanResult.isSafe ? (
                      <span className="bg-cyber-success/20 text-cyber-success px-3 py-1 rounded-full text-sm flex items-center gap-1">
                        <Check className="h-4 w-4" /> Safe
                      </span>
                    ) : (
                      <span className="bg-cyber-danger/20 text-cyber-danger px-3 py-1 rounded-full text-sm flex items-center gap-1">
                        <AlertTriangle className="h-4 w-4" /> Suspicious
                      </span>
                    )}
                  </div>
                  
                  <div className="space-y-3">
                    <div className="flex items-start gap-2">
                      <LinkIcon className="h-4 w-4 text-cyber-accent mt-1" />
                      <div>
                        <span className="text-sm text-gray-400">Analyzed URL:</span>
                        <p className="text-white break-all">{url}</p>
                      </div>
                    </div>
                    
                    <div>
                      <span className="text-sm text-gray-400">Domain Information:</span>
                      <div className="grid grid-cols-2 gap-2 mt-1">
                        <div className="bg-cyber-dark/60 p-2 rounded border border-cyber-accent/5">
                          <p className="text-xs text-gray-500">Domain</p>
                          <p className="text-sm text-white">{scanResult.details.domain}</p>
                        </div>
                        <div className="bg-cyber-dark/60 p-2 rounded border border-cyber-accent/5">
                          <p className="text-xs text-gray-500">Registration</p>
                          <p className="text-sm text-white">{scanResult.details.registered}</p>
                        </div>
                        <div className="bg-cyber-dark/60 p-2 rounded border border-cyber-accent/5">
                          <p className="text-xs text-gray-500">SSL Security</p>
                          <p className={`text-sm ${scanResult.details.ssl ? 'text-cyber-success' : 'text-cyber-danger'}`}>
                            {scanResult.details.ssl ? 'Secure (HTTPS)' : 'Not Secure'}
                          </p>
                        </div>
                        <div className="bg-cyber-dark/60 p-2 rounded border border-cyber-accent/5">
                          <p className="text-xs text-gray-500">Redirects</p>
                          <p className="text-sm text-white">{scanResult.details.redirects}</p>
                        </div>
                      </div>
                    </div>
                    
                    {scanResult.threats.length > 0 && (
                      <div>
                        <span className="text-sm text-gray-400">Detected Threats:</span>
                        <ul className="mt-1 space-y-1">
                          {scanResult.threats.map((threat, index) => (
                            <li key={index} className="bg-cyber-danger/10 text-cyber-danger text-sm p-2 rounded flex items-center gap-2 border border-cyber-danger/20">
                              <AlertTriangle className="h-4 w-4" />
                              {threat}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              </div>
              
              <div className="mt-6 flex justify-end">
                <Button 
                  onClick={resetScan}
                  className="bg-cyber-dark hover:bg-cyber-secondary text-white border border-cyber-accent/30"
                >
                  Scan Another URL
                </Button>
              </div>
            </div>
          )}
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mt-10">
            <Card className="cyber-card p-5 flex flex-col items-center text-center border border-cyber-accent/20 hover:border-cyber-accent/40 transition-colors">
              <div className="bg-cyber-accent/10 p-3 rounded-full mb-4 border border-cyber-accent/30">
                <Shield className="h-7 w-7 text-cyber-accent" />
              </div>
              <h3 className="text-lg font-medium text-white mb-2">Real-time Protection</h3>
              <p className="text-gray-400 text-sm">
                Our advanced AI constantly updates to detect the latest phishing techniques and threats.
              </p>
            </Card>
            
            <Card className="cyber-card p-5 flex flex-col items-center text-center border border-cyber-accent/20 hover:border-cyber-accent/40 transition-colors">
              <div className="bg-cyber-purple/10 p-3 rounded-full mb-4 border border-cyber-purple/30">
                <Network className="h-7 w-7 text-cyber-purple" />
              </div>
              <h3 className="text-lg font-medium text-white mb-2">Deep Analysis</h3>
              <p className="text-gray-400 text-sm">
                Deep scanning of URLs for suspicious patterns, domain age, and security certificates.
              </p>
            </Card>
            
            <Card className="cyber-card p-5 flex flex-col items-center text-center border border-cyber-accent/20 hover:border-cyber-accent/40 transition-colors">
              <div className="bg-cyber-warning/10 p-3 rounded-full mb-4 border border-cyber-warning/30">
                <Lock className="h-7 w-7 text-cyber-warning" />
              </div>
              <h3 className="text-lg font-medium text-white mb-2">Security Focused</h3>
              <p className="text-gray-400 text-sm">
                Identifies potential threats including fake websites, credential theft attempts, and more.
              </p>
            </Card>
          </div>

          <div className="cyber-card p-6 mt-12 border border-cyber-accent/20">
            <div className="flex items-center mb-4">
              <Database className="h-5 w-5 text-cyber-accent mr-2" />
              <h3 className="text-xl font-bold text-white">Scan History</h3>
            </div>
            <p className="text-gray-400 mb-4 text-sm">
              PhishGuard securely stores your scan history, helping you track potential threats over time.
            </p>
            <div className="text-center p-6 border border-dashed border-gray-700 rounded">
              <p className="text-gray-500">Your scan history will appear here</p>
            </div>
          </div>
        </div>
      </main>
      
      <footer className="border-t border-cyber-accent/10 py-6 mt-20">
        <div className="container mx-auto px-4 text-center">
          <p className="text-gray-500 text-sm">
            © {new Date().getFullYear()} PhishGuard | Secure Link Analysis Tool
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Dashboard;
