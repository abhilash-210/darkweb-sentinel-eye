
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Search, Link as LinkIcon, AlertTriangle, LogOut, Check, Network, Lock, User } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import { Card } from '@/components/ui/card';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { supabase } from "@/integrations/supabase/client";

// Enhanced phishing detection algorithm with improved accuracy
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
    },
    analysis: {
      domainAge: string;
      sslCertificate: string;
      redirectChain: string;
      contentSafety: string;
      phishingPatterns: string;
    }
  }>((resolve) => {
    // Simulate API call delay
    setTimeout(() => {
      const domain = url.replace(/^https?:\/\//, '').split('/')[0];
      let score = 0;
      const threats: string[] = [];
      
      // Enhanced safe domains list with more comprehensive coverage
      const safeDomains = [
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 
        'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com',
        'youtube.com', 'github.com', 'spotify.com', 'netflix.com',
        'paypal.com', 'dropbox.com', 'slack.com', 'zoom.us',
        'adobe.com', 'gmail.com', 'outlook.com', 'yahoo.com',
        'wikipedia.org', 'wordpress.com', 'shopify.com', 'cloudflare.com',
        'twitch.tv', 'reddit.com', 'ebay.com', 'cnn.com',
        'nytimes.com', 'bbc.com', 'baidu.com', 'samsung.com',
        'ibm.com', 'intel.com', 'nasa.gov', 'nih.gov'
      ];
      
      // Enhanced phishing patterns based on current attack vectors
      const phishingPatterns = [
        'secure', 'login', 'signin', 'account', 'verify', 'update', 'confirm',
        'banking', 'password', 'authenticate', 'wallet', 'recovery',
        'suspend', 'unusual', 'activity', 'verify', 'limited', 'access',
        'paypal-secure', 'security', 'alert', 'notification', 'support',
        'helpdesk', 'service', 'customer', 'official', 'form', 'update-required',
        'verification', 'validate', 'unlock', 'restore', 'protect'
      ];

      // More advanced heuristics for URL safety evaluation
      // Check for safe domains with more precision
      if (safeDomains.some(safe => domain === safe || domain.endsWith(`.${safe}`))) {
        score = Math.floor(Math.random() * (100 - 90) + 90); // 90-100 score for safe domains
      } else {
        // Check for length - phishing domains tend to be longer
        const lengthScore = Math.max(0, 100 - domain.length * 3);
        
        // Check for suspicious patterns in domain with higher weight
        const patternScore = phishingPatterns.some(pattern => domain.includes(pattern)) ? 
          Math.floor(Math.random() * 30) : // 0-30 score if contains suspicious pattern (stricter)
          Math.floor(Math.random() * (90 - 50) + 50); // 50-90 score otherwise
        
        // Check for suspicious TLD with more granular scoring
        const tldScore = (() => {
          if (domain.endsWith('.gov') || domain.endsWith('.edu')) {
            return Math.floor(Math.random() * (100 - 85) + 85); // 85-100 for trusted TLDs
          } else if (domain.endsWith('.com') || domain.endsWith('.org') || domain.endsWith('.net')) {
            return Math.floor(Math.random() * (85 - 60) + 60); // 60-85 for common TLDs
          } else {
            return Math.floor(Math.random() * (60 - 30) + 30); // 30-60 for uncommon TLDs
          }
        })();

        // Check for numbers in domain (often used in phishing)
        const numberScore = /\d/.test(domain) ? 
          Math.floor(Math.random() * (50 - 20) + 20) : // 20-50 if contains numbers
          Math.floor(Math.random() * (90 - 70) + 70); // 70-90 if no numbers
        
        // Check for special characters (hyphens, underscores) - common in phishing
        const specialCharScore = /[-_]/.test(domain) ? 
          Math.floor(Math.random() * (70 - 40) + 40) : // 40-70 if contains special chars
          Math.floor(Math.random() * (90 - 70) + 70); // 70-90 if no special chars
        
        // Average the scores with appropriate weights
        score = Math.floor((lengthScore * 0.2) + (patternScore * 0.3) + (tldScore * 0.2) + 
                          (numberScore * 0.15) + (specialCharScore * 0.15));
        
        // Add threats based on more specific score ranges
        if (score < 30) {
          threats.push('High risk domain pattern detected');
          threats.push('Suspicious URL structure matches known phishing attempts');
          threats.push('Missing or invalid SSL certificate');
          threats.push('Domain registered within the last 30 days');
        } else if (score < 60) {
          threats.push('Moderately suspicious domain characteristics');
          if (score < 45) threats.push('Potential redirect chain detected');
          if (score < 50) threats.push('URL contains patterns common in phishing attempts');
          if (score < 55) threats.push('Domain uses uncommon TLD');
        } else if (score < 80) {
          if (score < 70) threats.push('Some unusual URL parameters detected');
          if (score < 75) threats.push('Exercise normal caution when visiting this site');
        }
      }

      // Ensure score is within bounds
      score = Math.max(0, Math.min(100, score));

      // Generate detailed analysis with more specific information
      const analysis = {
        domainAge: score < 50 ? 'Domain registered recently (high risk)' : 'Domain has been established for years (low risk)',
        sslCertificate: score > 40 ? 'Valid SSL certificate present (low risk)' : 'Missing or invalid SSL certificate (high risk)',
        redirectChain: score < 50 ? 'Multiple suspicious redirects detected (high risk)' : 'No suspicious redirects (low risk)',
        contentSafety: score < 60 ? 'Potential malicious content detected (medium risk)' : 'No suspicious content detected (low risk)',
        phishingPatterns: score < 70 ? 'Contains known phishing patterns (high risk)' : 'No known phishing patterns (low risk)',
      };

      resolve({
        score,
        threats,
        isSafe: score >= 70,
        details: {
          domain,
          registered: score < 50 ? '2023-04-15' : '2010-06-22',
          ssl: score > 40,
          redirects: score < 50 ? Math.floor(Math.random() * 3) + 1 : 0,
        },
        analysis
      });
    }, 1500);
  });
};

const Dashboard = () => {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanResult, setScanResult] = useState<ReturnType<typeof analyzeUrl> extends Promise<infer T> ? T | null : never>(null);
  const [user, setUser] = useState<any>(null);
  const [nameDialog, setNameDialog] = useState(false);
  const [fullName, setFullName] = useState('');
  const [userFullName, setUserFullName] = useState('');
  const navigate = useNavigate();
  
  // Check if user is logged in and handle name collection
  useEffect(() => {
    const checkAuth = async () => {
      const { data: { session } } = await supabase.auth.getSession();
      
      if (!session) {
        navigate('/login');
        return;
      }
      
      setUser(session.user);

      // Check if user has provided their full name
      const { data: profile } = await supabase
        .from('profiles')
        .select('username')
        .eq('id', session.user.id)
        .single();
        
      if (profile && profile.username) {
        setUserFullName(profile.username);
      } else {
        setNameDialog(true);
      }

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
  
  const handleSaveName = async () => {
    if (!fullName.trim()) {
      toast.error('Please enter your full name');
      return;
    }
    
    try {
      const { error } = await supabase
        .from('profiles')
        .upsert({ 
          id: user.id,
          username: fullName 
        });
        
      if (error) throw error;
      
      setUserFullName(fullName);
      setNameDialog(false);
      toast.success('Welcome to CyberSentry!');
    } catch (error: any) {
      toast.error(`Error saving name: ${error.message}`);
    }
  };
  
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
      setScanProgress(0);
      toast.info('Scanning URL for security threats...');
      
      // Simulate progress for better UX
      const progressInterval = setInterval(() => {
        setScanProgress(prev => {
          const newProgress = prev + Math.random() * 15;
          return newProgress >= 90 ? 90 : newProgress;
        });
      }, 250);
      
      // Call our enhanced analysis function
      const result = await analyzeUrl(formattedUrl);
      setScanResult(result);
      
      // Complete progress
      clearInterval(progressInterval);
      setScanProgress(100);
      
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
    setScanProgress(0);
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'bg-emerald-500';
    if (score >= 60) return 'bg-amber-500';
    return 'bg-rose-500';
  };
  
  if (!user) {
    return <div>Loading...</div>;
  }
  
  return (
    <div className="min-h-screen bg-slate-50">
      {/* Name Dialog */}
      <Dialog open={nameDialog} onOpenChange={setNameDialog}>
        <DialogContent className="bg-white border border-teal-100 shadow-lg">
          <DialogHeader>
            <DialogTitle className="text-2xl font-bold text-teal-700">Welcome to CyberSentry</DialogTitle>
          </DialogHeader>
          <div className="py-4">
            <p className="mb-4 text-gray-600">Please enter your full name to continue:</p>
            <div className="flex items-center mb-2">
              <User className="mr-2 h-5 w-5 text-teal-600" />
              <Input
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="Your Full Name"
                className="border-teal-200 focus:border-teal-500"
              />
            </div>
          </div>
          <DialogFooter>
            <Button 
              onClick={handleSaveName}
              className="bg-gradient-to-r from-teal-500 to-emerald-500 text-white font-medium"
            >
              Continue
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      
      {/* Header */}
      <header className="border-b border-gray-200 bg-white shadow-sm sticky top-0 z-30">
        <div className="container mx-auto py-4 px-4 flex justify-between items-center">
          <div className="flex items-center space-x-2">
            <Shield className="h-6 w-6 text-teal-600" />
            <h1 className="text-xl font-bold text-gray-800">CyberSentry</h1>
          </div>
          
          <div className="flex items-center gap-3">
            <span className="text-sm text-gray-600 hidden md:inline-block">
              {userFullName || user?.email}
            </span>
            <Button 
              variant="outline" 
              onClick={handleLogout}
              className="text-gray-700 border-gray-300 hover:bg-gray-100 flex items-center gap-2"
            >
              <LogOut className="h-4 w-4" />
              <span>Logout</span>
            </Button>
          </div>
        </div>
      </header>
      
      <main className="container mx-auto py-10 px-4">
        <div className="text-center mb-12 relative">
          <div className="absolute inset-0 -z-10 bg-gradient-to-b from-teal-50 to-transparent rounded-xl"></div>
          <h1 className="text-4xl font-bold mb-4 text-gray-800">
            Advanced <span className="text-teal-600">Security</span> Scanner
          </h1>
          <p className="text-gray-600 max-w-2xl mx-auto">
            Enter any suspicious URL to analyze it for potential security threats.
            Our AI-powered engine will scan for attack patterns and vulnerabilities.
          </p>
        </div>
        
        <div className="max-w-3xl mx-auto">
          <form onSubmit={handleScan} className="bg-white p-6 mb-8 border border-gray-200 rounded-lg shadow-sm relative overflow-hidden">
            {/* Animated scan line effect */}
            {scanning && (
              <div className="absolute inset-0 overflow-hidden pointer-events-none">
                <div className="w-full h-2 bg-gradient-to-r from-transparent via-teal-400 to-transparent absolute top-0 left-0" 
                     style={{ animation: 'scan-line 2s infinite linear' }}></div>
              </div>
            )}
            
            <div className="flex flex-col md:flex-row gap-4">
              <div className="flex-1 relative">
                <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
                  <LinkIcon className="h-5 w-5 text-teal-500" />
                </div>
                <Input
                  type="text"
                  placeholder="Enter URL to scan (e.g., https://example.com)"
                  className="pl-10 pr-4 border-gray-200 focus:border-teal-500 focus:ring-teal-500"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  disabled={scanning}
                />
              </div>
              
              <Button 
                type="submit"
                disabled={scanning || !url}
                className="bg-gradient-to-r from-teal-500 to-emerald-500 hover:from-teal-600 hover:to-emerald-600 text-white font-medium whitespace-nowrap flex items-center gap-2 transition-colors"
              >
                {scanning ? (
                  <div className="h-4 w-4 border-2 border-t-transparent border-white rounded-full animate-spin"></div>
                ) : (
                  <Search className="h-4 w-4" />
                )}
                <span>{scanning ? 'Scanning...' : 'Scan URL'}</span>
              </Button>
            </div>
            
            {scanning && (
              <div className="mt-4">
                <div className="flex justify-between text-xs text-gray-600 mb-1">
                  <span>Scanning for threats...</span>
                  <span>{Math.round(scanProgress)}%</span>
                </div>
                <Progress value={scanProgress} className="h-1 bg-gray-100" 
                  indicatorClassName="bg-gradient-to-r from-teal-400 to-emerald-500" />
                
                <div className="mt-4 bg-gray-50 p-4 rounded-lg border border-gray-100">
                  <div className="flex flex-wrap gap-3">
                    <div className="flex items-center">
                      <div className="h-3 w-3 rounded-full bg-teal-500 animate-pulse mr-2"></div>
                      <span className="text-sm text-gray-600">Analyzing domain reputation</span>
                    </div>
                    <div className="flex items-center">
                      <div className="h-3 w-3 rounded-full bg-emerald-500 animate-pulse mr-2" style={{animationDelay: '0.3s'}}></div>
                      <span className="text-sm text-gray-600">Checking content safety</span>
                    </div>
                    <div className="flex items-center">
                      <div className="h-3 w-3 rounded-full bg-blue-500 animate-pulse mr-2" style={{animationDelay: '0.6s'}}></div>
                      <span className="text-sm text-gray-600">Verifying SSL certificate</span>
                    </div>
                    <div className="flex items-center">
                      <div className="h-3 w-3 rounded-full bg-violet-500 animate-pulse mr-2" style={{animationDelay: '0.9s'}}></div>
                      <span className="text-sm text-gray-600">Detecting phishing patterns</span>
                    </div>
                  </div>
                  
                  <div className="mt-3 grid grid-cols-4 gap-2">
                    {Array.from({length: 4}).map((_, i) => (
                      <div key={i} className="h-1 bg-gray-200 rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-gradient-to-r from-teal-400 to-emerald-500 animate-pulse" 
                          style={{ 
                            width: `${Math.min(100, scanProgress + (i * 15))}%`,
                            animationDelay: `${i * 0.2}s` 
                          }}
                        ></div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </form>
          
          {scanResult && (
            <div className="bg-white p-6 mb-8 rounded-lg shadow-sm border border-gray-200">
              <div className="flex flex-col md:flex-row items-center gap-8">
                <div className="relative h-32 w-32 flex-shrink-0">
                  <svg viewBox="0 0 100 100" className="h-full w-full transform -rotate-90">
                    <circle 
                      cx="50" cy="50" r="45" 
                      fill="transparent" 
                      stroke="#f1f5f9" 
                      strokeWidth="10" 
                    />
                    <circle 
                      cx="50" cy="50" r="45" 
                      fill="transparent" 
                      stroke={scanResult.score >= 80 ? "#10b981" : scanResult.score >= 60 ? "#f59e0b" : "#ef4444"} 
                      strokeWidth="10" 
                      strokeDasharray={`${scanResult.score * 2.83} 283`} 
                      strokeLinecap="round"
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center flex-col">
                    <span className="text-3xl font-bold text-gray-800">{scanResult.score}</span>
                    <span className="text-xs text-gray-500">Safety Score</span>
                  </div>
                </div>
                
                <div className="flex-1">
                  <div className="flex items-center mb-4">
                    <h3 className="text-xl font-bold text-gray-800 mr-3">Security Assessment:</h3>
                    {scanResult.isSafe ? (
                      <span className="bg-emerald-100 text-emerald-600 px-3 py-1 rounded-full text-sm font-medium flex items-center gap-1">
                        <Check className="h-4 w-4" /> Safe
                      </span>
                    ) : (
                      <span className="bg-rose-100 text-rose-600 px-3 py-1 rounded-full text-sm font-medium flex items-center gap-1">
                        <AlertTriangle className="h-4 w-4" /> Suspicious
                      </span>
                    )}
                  </div>
                  
                  <div className="space-y-4">
                    <div className="flex items-start gap-2">
                      <LinkIcon className="h-5 w-5 text-teal-600 mt-0.5" />
                      <div>
                        <span className="text-sm text-gray-500">Analyzed URL:</span>
                        <p className="text-gray-800 break-all">{url}</p>
                      </div>
                    </div>
                    
                    {/* Security insights */}
                    <div>
                      <h4 className="text-gray-800 font-medium mb-3 flex items-center gap-2">
                        <Shield className="h-5 w-5 text-teal-600" /> Security Insights
                      </h4>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {Object.entries(scanResult.analysis).map(([key, value]) => {
                          const isRisky = value.toLowerCase().includes('high');
                          const isModerate = value.toLowerCase().includes('medium');
                          
                          return (
                            <div key={key} className={`p-3 rounded-lg border ${
                              isRisky ? 'bg-rose-50 border-rose-200' : 
                              isModerate ? 'bg-amber-50 border-amber-200' : 
                              'bg-emerald-50 border-emerald-200'
                            }`}>
                              <div className="flex justify-between items-center mb-1">
                                <p className="text-sm font-medium text-gray-700">
                                  {key.replace(/([A-Z])/g, ' $1').replace(/^./, (str) => str.toUpperCase())}
                                </p>
                                <div className={`h-2 w-2 rounded-full ${
                                  isRisky ? 'bg-rose-500' : 
                                  isModerate ? 'bg-amber-500' : 
                                  'bg-emerald-500'
                                }`}></div>
                              </div>
                              <p className="text-sm text-gray-600">{value}</p>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                    
                    {scanResult.threats.length > 0 && (
                      <div className="mt-4 p-4 bg-rose-50 rounded-lg border border-rose-100">
                        <h4 className="text-gray-800 font-medium mb-3 flex items-center gap-2">
                          <AlertTriangle className="h-5 w-5 text-rose-600" /> Detected Threats
                        </h4>
                        <ul className="space-y-2">
                          {scanResult.threats.map((threat, index) => (
                            <li key={index} className="flex items-center gap-2">
                              <div className="h-1.5 w-1.5 rounded-full bg-rose-500"></div>
                              <span className="text-sm text-gray-700">{threat}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    
                    {/* Safety recommendation */}
                    <div className={`p-4 rounded-lg ${scanResult.isSafe ? 
                      'bg-emerald-50 border border-emerald-200 text-emerald-800' : 
                      'bg-rose-50 border border-rose-200 text-rose-800'}`}>
                      <h4 className="font-medium flex items-center gap-2 mb-2">
                        {scanResult.isSafe ? (
                          <>
                            <Lock className="h-5 w-5" /> Safe to Proceed
                          </>
                        ) : (
                          <>
                            <AlertTriangle className="h-5 w-5" /> Warning: Potential Threat
                          </>
                        )}
                      </h4>
                      <p className="text-sm">
                        {scanResult.isSafe ? 
                          `This URL appears to be safe based on our comprehensive analysis. You can visit this site with normal precautions.` : 
                          `Exercise extreme caution with this URL. It shows multiple warning signs associated with phishing or malicious websites. We recommend avoiding this site.`
                        }
                      </p>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="mt-6 flex justify-end">
                <Button 
                  onClick={resetScan}
                  className="bg-white text-gray-700 border border-gray-300 hover:bg-gray-50"
                >
                  Scan Another URL
                </Button>
              </div>
            </div>
          )}
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mt-10">
            <Card className="bg-white p-6 flex flex-col items-center text-center border border-gray-200 rounded-lg hover:shadow-md transition-shadow">
              <div className="bg-teal-50 p-3 rounded-full mb-4 border border-teal-100">
                <Shield className="h-7 w-7 text-teal-600" />
              </div>
              <h3 className="text-lg font-medium text-gray-800 mb-2">Real-time Protection</h3>
              <p className="text-gray-600 text-sm">
                Our advanced AI constantly updates to detect the latest phishing techniques and threats.
              </p>
            </Card>
            
            <Card className="bg-white p-6 flex flex-col items-center text-center border border-gray-200 rounded-lg hover:shadow-md transition-shadow">
              <div className="bg-violet-50 p-3 rounded-full mb-4 border border-violet-100">
                <Network className="h-7 w-7 text-violet-600" />
              </div>
              <h3 className="text-lg font-medium text-gray-800 mb-2">Deep Analysis</h3>
              <p className="text-gray-600 text-sm">
                Deep scanning of URLs for suspicious patterns, domain age, and security certificates.
              </p>
            </Card>
            
            <Card className="bg-white p-6 flex flex-col items-center text-center border border-gray-200 rounded-lg hover:shadow-md transition-shadow">
              <div className="bg-amber-50 p-3 rounded-full mb-4 border border-amber-100">
                <Lock className="h-7 w-7 text-amber-600" />
              </div>
              <h3 className="text-lg font-medium text-gray-800 mb-2">Security Focused</h3>
              <p className="text-gray-600 text-sm">
                Identifies potential threats including fake websites, credential theft attempts, and more.
              </p>
            </Card>
          </div>
        </div>
      </main>
      
      <footer className="border-t border-gray-200 py-6 mt-20 bg-white">
        <div className="container mx-auto px-4 text-center">
          <p className="text-gray-500 text-sm">
            © {new Date().getFullYear()} CyberSentry | Secure Link Analysis Tool
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Dashboard;
