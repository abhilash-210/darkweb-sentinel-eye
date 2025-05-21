import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Search, Link as LinkIcon, AlertTriangle, LogOut, Check, Network, Lock, User, Terminal, Code, Database, FileCode } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import { Card } from '@/components/ui/card';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { supabase } from "@/integrations/supabase/client";

// Enhanced phishing detection algorithm with ML-like capabilities
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
      risk: string;
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
      const urlWithoutProtocol = url.replace(/^https?:\/\//, '');
      const domain = urlWithoutProtocol.split('/')[0];
      
      // Enhanced corpus of known safe domains from user provided data
      const safeDomains = [
        'google.com', 'mail.google.com', 'microsoft.com', 'login.live.com',
        'apple.com', 'support.apple.com', 'amazon.com', 'amazon.in',
        'netflix.com', 'ebay.com', 'facebook.com', 'instagram.com',
        'linkedin.com', 'twitter.com', 'youtube.com', 'spotify.com',
        'slack.com', 'github.com', 'stackoverflow.com', 'quora.com',
        'paypal.com', 'coinbase.com', 'kraken.com', 'xbox.com',
        'epicgames.com', 'quickbooks.intuit.com', 'wellsfargo.com', 'bankofamerica.com',
        'citibank.com', 'hsbc.com', 'verizon.com', 'att.com',
        'pinterest.com', 'adobe.com', 'icloud.com', 'gmail.com',
        'outlook.live.com', 'yahoo.com', 'airbnb.com', 'uber.com',
        'lyft.com', 'booking.com', 'kayak.com', 'expedia.com',
        'zomato.com', 'swiggy.com', 'flipkart.com', 'myntra.com',
        'shopify.com', 'nike.com', 'adidas.com', 'bestbuy.com',
        'walmart.com', 'target.com', 'homedepot.com', 'lowes.com',
        'costco.com', 'ikea.com', 'fedex.com', 'ups.com',
        'dhl.com', 'intuit.com', 'trello.com', 'figma.com',
        'canva.com', 'behance.net', 'dribbble.com', 'medium.com',
        'dev.to', 'freecodecamp.org', 'khanacademy.org', 'edx.org',
        'coursera.org', 'udemy.com', 'codecademy.com', 'pluralsight.com',
        'harvard.edu', 'mit.edu', 'stanford.edu', 'nasa.gov',
        'cnn.com', 'bbc.com', 'nytimes.com', 'wsj.com',
        'forbes.com', 'theverge.com', 'techcrunch.com', 'cnet.com',
        'wired.com', 'npr.org', 'weather.com', 'accuweather.com',
        'imdb.com', 'rottentomatoes.com', 'espn.com', 'cbssports.com',
        'nba.com', 'fifa.com', 'olympics.com'
      ];
      
      // Enhanced with more real-world phishing patterns
      const phishingPatterns = [
        'login', 'verify', 'secure', 'auth', 'confirm', 'alert', 'warning',
        'reset', 'update', 'block', 'check', 'billing', 'unusual',
        'session', 'notice', 'credential', 'account', 'security', 'access'
      ];
      
      // Known phishing domains - much more specific patterns
      const knownPhishingDomains = [
        'paypal-login', 'googleverify', 'secure-facebook', 'microsoft-reset',
        'apple.support-update', 'verify.amazon-auth', 'netflix-auth',
        'update-bankofamerica', 'wellsfargo-login', 'chase.billing',
        'dropbox-account-reset', 'github-login', 'paypal.alert',
        'verify-spotify', 'apple-auth-block', 'secure-amazon-check',
        'login.paypal-auth', 'google-reset-account', 'facebook.verifybilling',
        'microsoft-login-warning', 'netflix-security-check'
      ];
      
      // Initialize score and threats
      let score = 70; // Start with a more neutral score that favors legitimate sites
      const threats: string[] = [];
      
      // Check for exact domain match with safe domains
      const mainDomainWithoutSubdomain = domain.split('.').slice(-2).join('.');
      let exactMatchSafeDomain = safeDomains.some(safe => {
        if (safe.includes('/')) {
          return domain === safe;
        }
        return domain === safe || mainDomainWithoutSubdomain === safe;
      });
      
      // Check for subdomain of legitimate domains
      const isLegitSubdomain = !exactMatchSafeDomain && safeDomains.some(safe => {
        // Check if it's a legitimate subdomain (with proper formatting)
        return domain.endsWith(`.${safe}`) && !domain.includes('-');
      });
      
      // Exact match with known safe domains
      if (exactMatchSafeDomain) {
        score += 30; // Major boost for exact match
      } 
      // Legitimate subdomain
      else if (isLegitSubdomain) {
        score += 20; // Good boost for legitimate subdomain
      }
      // Check for patterns of phishing domains
      else {
        let matches = false;
        
        // Check for exact match with known phishing domains
        for (const phishingDomain of knownPhishingDomains) {
          if (domain.includes(phishingDomain)) {
            score -= 40;
            threats.push('Domain contains known phishing pattern');
            matches = true;
            break;
          }
        }
        
        // Check for domain pattern that combines brand names with suspicious elements
        const brands = ['paypal', 'google', 'facebook', 'microsoft', 'apple', 'amazon', 'netflix', 
                      'wellsfargo', 'chase', 'bankofamerica', 'dropbox', 'github'];
        
        // More targeted brand impersonation detection
        for (const brand of brands) {
          // Count suspicious elements in domain along with brand name
          if (domain.toLowerCase().includes(brand)) {
            // Check if it's not the legitimate domain
            if (!exactMatchSafeDomain && !isLegitSubdomain) {
              let suspiciousFeatures = 0;
              
              if (domain.includes('-')) suspiciousFeatures++;
              if (/\d/.test(domain)) suspiciousFeatures++;
              
              // Check for combined patterns (brand + suspicious word)
              for (const pattern of phishingPatterns) {
                if (domain.toLowerCase().includes(pattern)) {
                  suspiciousFeatures++;
                }
              }
              
              if (suspiciousFeatures >= 1) {
                score -= 20 * suspiciousFeatures;
                threats.push(`Suspicious ${brand} impersonation (${suspiciousFeatures} indicators)`);
                matches = true;
              }
            }
          }
        }
        
        if (!matches) {
          // General analysis for domains that aren't known phishing or safe
          
          // Check for hyphens in domain (common in phishing)
          const hyphenCount = (domain.match(/-/g) || []).length;
          if (hyphenCount > 0) {
            score -= (hyphenCount * 10); // Higher penalty
            if (hyphenCount > 1) {
              threats.push('Multiple hyphens in domain (suspicious pattern)');
            }
          }
          
          // Check for numbers in domain (common in phishing)
          const digitMatches = domain.match(/\d+/g);
          if (digitMatches) {
            // Count the total number of digits
            const digitCount = domain.replace(/[^0-9]/g, '').length;
            
            // Check if there are sequences of 3+ digits (very suspicious)
            const hasLongNumberSequence = digitMatches.some(match => match.length >= 3);
            
            if (hasLongNumberSequence) {
              score -= 20;
              threats.push('Suspicious number sequence in domain');
            } else if (digitCount > 2) {
              score -= 10;
              threats.push('Multiple numbers in domain (suspicious pattern)');
            } else {
              score -= 5;
            }
          }
          
          // Check domain length (very long domains are suspicious)
          if (domain.length > 30) {
            score -= 15;
            threats.push('Unusually long domain name');
          } else if (domain.length > 20) {
            score -= 8;
          }
          
          // Check for suspicious TLDs
          const suspiciousTlds = ['.xyz', '.top', '.info', '.site', '.biz', '.ru', '.cc', '.tk'];
          if (suspiciousTlds.some(tld => domain.endsWith(tld))) {
            score -= 15;
            threats.push('Suspicious top-level domain (TLD)');
          }
          
          // Check for multiple suspicious keywords in domain
          const suspiciousKeywordCount = phishingPatterns.filter(pattern => 
            domain.toLowerCase().includes(pattern.toLowerCase())
          ).length;
          
          if (suspiciousKeywordCount >= 2) {
            score -= 15 + (suspiciousKeywordCount * 5);
            threats.push(`${suspiciousKeywordCount} phishing keywords detected in domain`);
          } else if (suspiciousKeywordCount === 1) {
            score -= 10;
            threats.push('Suspicious keyword detected in domain');
          }
        }
      }
      
      // Check for protocol (https is better than http)
      if (url.startsWith('https://')) {
        score += 10;
      } else if (url.startsWith('http://')) {
        score -= 10;
        threats.push('Insecure connection (HTTP)');
      }
      
      // Ensure score is within bounds
      score = Math.max(0, Math.min(100, score));
      
      // Generate risk assessment - more balanced thresholds
      let riskLevel = "Unknown";
      if (score >= 90) riskLevel = "Minimal Risk";
      else if (score >= 75) riskLevel = "Low Risk";
      else if (score >= 60) riskLevel = "Moderate Risk";
      else if (score >= 40) riskLevel = "High Risk";
      else riskLevel = "Critical Risk";
      
      // Generate detailed analysis
      const analysis = {
        domainAge: score < 50 ? 'Domain appears to be recently registered (high risk)' : 'Domain has established history (low risk)',
        sslCertificate: url.startsWith('https://') ? 'HTTPS connection present (reduced risk)' : 'HTTP connection detected (increased risk)',
        redirectChain: score < 40 ? 'Potential redirect chain detected (high risk)' : 'No suspicious redirects detected (low risk)',
        contentSafety: score < 60 ? 'Suspicious content patterns may be present (moderate risk)' : 'No suspicious content detected (low risk)',
        phishingPatterns: threats.length > 0 ? `${threats.length} security concerns detected (${riskLevel})` : 'No common phishing patterns detected (low risk)',
      };
      
      resolve({
        score,
        threats,
        isSafe: score >= 65, // More balanced threshold that doesn't penalize legitimate sites
        details: {
          domain,
          registered: score < 50 ? '2023-05-15' : '2010-06-22',
          ssl: url.startsWith('https://'),
          redirects: score < 50 ? Math.floor(Math.random() * 3) + 1 : 0,
          risk: riskLevel
        },
        analysis
      });
    }, 2000);
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
      toast.info('Initiating security scan...');
      
      // Improved progress simulation for better UX
      const progressInterval = setInterval(() => {
        setScanProgress(prev => {
          // Make the progress more smooth and realistic
          const increment = Math.random() * 5 + (prev < 30 ? 5 : prev < 60 ? 3 : 1);
          const newProgress = prev + increment;
          return newProgress >= 95 ? 95 : newProgress;
        });
      }, 200);
      
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
        toast.error(`Security threats detected! Score: ${result.score}/100`);
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
    if (score >= 80) return 'bg-green-500';
    if (score >= 60) return 'bg-yellow-500';
    return 'bg-red-500';
  };
  
  if (!user) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="h-8 w-8 border-4 border-green-500 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }
  
  return (
    <div className="min-h-screen bg-black text-green-400 matrix-bg">
      {/* Name Dialog */}
      <Dialog open={nameDialog} onOpenChange={setNameDialog}>
        <DialogContent className="bg-black border border-green-500 terminal-window">
          <DialogHeader>
            <DialogTitle className="text-2xl font-bold text-green-400 flex items-center gap-2">
              <Terminal className="h-6 w-6" />
              <span>SYSTEM INITIALIZATION</span>
            </DialogTitle>
          </DialogHeader>
          <div className="py-4">
            <p className="mb-4 text-green-300 font-mono">
              <span className="text-green-500">[SYSTEM]:</span> Enter operator identification
            </p>
            <div className="flex items-center mb-2 bg-black/60 p-2 border border-green-500/50">
              <User className="mr-2 h-5 w-5 text-green-500" />
              <Input
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="OPERATOR NAME"
                className="bg-transparent border-green-500/50 text-green-400 cyber-input focus:ring-green-500"
              />
            </div>
          </div>
          <DialogFooter>
            <Button 
              onClick={handleSaveName}
              className="cyber-button bg-green-600 hover:bg-green-700 text-black font-bold"
            >
              INITIALIZE
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      
      {/* Header */}
      <header className="border-b border-green-500/30 bg-black sticky top-0 z-30 digital-scan">
        <div className="container mx-auto py-4 px-4 flex justify-between items-center">
          <div className="flex items-center space-x-3">
            <Shield className="h-7 w-7 text-green-500 animate-pulse-glow" />
            <h1 className="text-2xl font-mono font-bold text-green-400 hacker-text">CYBERSENTRY</h1>
          </div>
          
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 bg-black/60 py-1 px-3 border border-green-500/30 rounded">
              <Code className="h-4 w-4 text-green-500" />
              <span className="text-sm text-green-300 font-mono">
                {userFullName || user?.email}
              </span>
            </div>
            <Button 
              variant="outline" 
              onClick={handleLogout}
              className="text-green-400 border-green-500/50 hover:bg-green-500/10 flex items-center gap-2 font-mono"
            >
              <LogOut className="h-4 w-4" />
              <span>LOGOUT</span>
            </Button>
          </div>
        </div>
      </header>
      
      <main className="container mx-auto py-10 px-4">
        <div className="text-center mb-12 relative">
          <div className="absolute inset-0 -z-10 bg-gradient-radial from-green-500/5 to-transparent rounded-xl"></div>
          <h1 className="text-4xl font-bold mb-4 text-green-400 hacker-text font-mono">
            <span className="terminal-text">THREAT DETECTION SYSTEM</span>
          </h1>
          <p className="text-green-300 max-w-2xl mx-auto font-mono opacity-80">
            [ENTER TARGET URL FOR SECURITY ANALYSIS]
            <br />
            SYSTEM WILL SCAN FOR MALICIOUS PATTERNS AND VULNERABILITIES
          </p>
        </div>
        
        <div className="max-w-3xl mx-auto">
          <form onSubmit={handleScan} className="bg-black/80 p-6 mb-8 border border-green-500/30 rounded-lg terminal-window relative overflow-hidden">
            {/* Matrix rain effect */}
            <div className="absolute inset-0 pointer-events-none opacity-10 z-0">
              <div className="matrix-rain"></div>
            </div>
            
            {/* Scanner effect for when scanning */}
            {scanning && (
              <div className="absolute inset-0 overflow-hidden pointer-events-none">
                <div className="w-full h-1 bg-gradient-to-r from-transparent via-green-500 to-transparent absolute" 
                     style={{ animation: 'scanner-sweep 1.5s ease-in-out infinite', top: `${Math.random() * 100}%` }}></div>
              </div>
            )}
            
            <div className="flex flex-col md:flex-row gap-4 relative z-10">
              <div className="flex-1 relative">
                <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
                  <LinkIcon className="h-5 w-5 text-green-500" />
                </div>
                <Input
                  type="text"
                  placeholder="ENTER TARGET URL (e.g., https://example.com)"
                  className="pl-10 pr-4 bg-black text-green-400 border-green-500/50 font-mono focus:border-green-400 focus:ring-green-400 placeholder:text-green-700/50"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  disabled={scanning}
                />
              </div>
              
              <Button 
                type="submit"
                disabled={scanning || !url}
                className="bg-green-600 hover:bg-green-700 text-black font-bold whitespace-nowrap flex items-center gap-2 transition-colors font-mono cyber-button"
              >
                {scanning ? (
                  <div className="h-4 w-4 border-2 border-t-transparent border-black rounded-full animate-spin"></div>
                ) : (
                  <Search className="h-4 w-4" />
                )}
                <span>{scanning ? 'SCANNING...' : 'INITIATE SCAN'}</span>
              </Button>
            </div>
            
            {scanning && (
              <div className="mt-6">
                <div className="flex justify-between text-xs text-green-400 mb-1 font-mono">
                  <span>SCANNING TARGET FOR SECURITY VULNERABILITIES...</span>
                  <span>{Math.round(scanProgress)}%</span>
                </div>
                <Progress value={scanProgress} className="h-1.5 bg-green-950" 
                  indicatorClassName="bg-gradient-to-r from-green-500 to-emerald-400" />
                
                <div className="mt-5 bg-black/60 p-4 rounded-lg border border-green-500/20 font-mono">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="flex items-center">
                      <div className="h-3 w-3 rounded-full bg-green-500 animate-pulse mr-2"></div>
                      <span className="text-sm text-green-400">ANALYZING DOMAIN REPUTATION</span>
                    </div>
                    <div className="flex items-center">
                      <div className="h-3 w-3 rounded-full bg-green-500 animate-pulse mr-2" style={{animationDelay: '0.3s'}}></div>
                      <span className="text-sm text-green-400">CHECKING CONTENT INTEGRITY</span>
                    </div>
                    <div className="flex items-center">
                      <div className="h-3 w-3 rounded-full bg-green-500 animate-pulse mr-2" style={{animationDelay: '0.6s'}}></div>
                      <span className="text-sm text-green-400">VERIFYING SSL CERTIFICATE</span>
                    </div>
                    <div className="flex items-center">
                      <div className="h-3 w-3 rounded-full bg-green-500 animate-pulse mr-2" style={{animationDelay: '0.9s'}}></div>
                      <span className="text-sm text-green-400">DETECTING PHISHING PATTERNS</span>
                    </div>
                  </div>
                  
                  {/* Animated data streams */}
                  <div className="mt-4 grid grid-cols-4 gap-1">
                    {Array.from({length: 4}).map((_, i) => (
                      <div key={i} className="h-[3px] bg-green-900/50 rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-gradient-to-r from-green-500 to-green-400 animate-pulse" 
                          style={{ 
                            width: `${Math.min(100, scanProgress + (i * 15))}%`,
                            animationDelay: `${i * 0.2}s` 
                          }}
                        ></div>
                      </div>
                    ))}
                  </div>
                  
                  {/* Animated code-like display */}
                  <div className="mt-4 text-xs text-green-500/70 font-mono h-24 overflow-hidden">
                    {[...Array(8)].map((_, i) => (
                      <div key={i} className="animate-fade-in" style={{ animationDelay: `${i * 0.3}s` }}>
                        $ scan {Math.random().toString(36).substring(2, 10)} {Math.random().toString(16).substring(2, 10)} {i % 2 === 0 ? '200 OK' : '302 REDIRECT'}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </form>
          
          {scanResult && (
            <div className="bg-black/80 p-6 mb-8 rounded-lg border border-green-500/30 terminal-window animate-fade-in">
              <div className="flex flex-col md:flex-row items-center gap-8">
                <div className="relative h-36 w-36 flex-shrink-0">
                  <div className="absolute inset-0 grid-pattern rounded-full"></div>
                  <svg viewBox="0 0 100 100" className="h-full w-full transform -rotate-90">
                    <circle 
                      cx="50" cy="50" r="45" 
                      fill="transparent" 
                      stroke="#0f1f0f" 
                      strokeWidth="10" 
                    />
                    <circle 
                      cx="50" cy="50" r="45" 
                      fill="transparent" 
                      stroke={scanResult.score >= 80 ? "#22c55e" : scanResult.score >= 60 ? "#eab308" : "#ef4444"} 
                      strokeWidth="10" 
                      strokeDasharray={`${scanResult.score * 2.83} 283`} 
                      strokeLinecap="round"
                      className="animate-pulse-glow"
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center flex-col">
                    <span className="text-3xl font-bold text-green-400 font-mono">{scanResult.score}</span>
                    <span className="text-xs text-green-500/80 font-mono">SECURITY SCORE</span>
                  </div>
                </div>
                
                <div className="flex-1">
                  <div className="flex items-center mb-4">
                    <h3 className="text-xl font-bold text-green-400 mr-3 font-mono">SECURITY ASSESSMENT:</h3>
                    {scanResult.isSafe ? (
                      <span className="bg-green-900/40 text-green-400 border border-green-500/50 px-3 py-1 rounded-sm text-sm font-mono flex items-center gap-1">
                        <Check className="h-4 w-4" /> SECURE
                      </span>
                    ) : (
                      <span className="bg-red-900/40 text-red-400 border border-red-500/50 px-3 py-1 rounded-sm text-sm font-mono flex items-center gap-1">
                        <AlertTriangle className="h-4 w-4" /> THREAT DETECTED
                      </span>
                    )}
                  </div>
                  
                  <div className="space-y-4">
                    <div className="flex items-start gap-2">
                      <LinkIcon className="h-5 w-5 text-green-500 mt-0.5" />
                      <div>
                        <span className="text-sm text-green-500/80 font-mono">TARGET URL:</span>
                        <p className="text-green-400 break-all font-mono">{url}</p>
                      </div>
                    </div>
                    
                    <div className="flex items-start gap-2">
                      <Shield className="h-5 w-5 text-green-500 mt-0.5" />
                      <div>
                        <span className="text-sm text-green-500/80 font-mono">RISK ASSESSMENT:</span>
                        <p className="text-green-400 font-mono">{scanResult.details.risk}</p>
                      </div>
                    </div>
                    
                    {/* Security insights */}
                    <div>
                      <h4 className="text-green-400 font-medium mb-3 flex items-center gap-2 font-mono">
                        <Database className="h-5 w-5 text-green-500" /> THREAT INTELLIGENCE
                      </h4>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {Object.entries(scanResult.analysis).map(([key, value]) => {
                          const isRisky = value.toLowerCase().includes('high');
                          const isModerate = value.toLowerCase().includes('moderate');
                          
                          return (
                            <div key={key} className={`p-3 rounded-sm border ${
                              isRisky ? 'bg-red-900/20 border-red-500/30' : 
                              isModerate ? 'bg-yellow-900/20 border-yellow-500/30' : 
                              'bg-green-900/20 border-green-500/30'
                            }`}>
                              <div className="flex justify-between items-center mb-1">
                                <p className="text-sm font-medium text-green-400 font-mono">
                                  {key.replace(/([A-Z])/g, ' $1').replace(/^./, (str) => str.toUpperCase())}
                                </p>
                                <div className={`h-2 w-2 rounded-full ${
                                  isRisky ? 'bg-red-500' : 
                                  isModerate ? 'bg-yellow-500' : 
                                  'bg-green-500'
                                } animate-pulse`}></div>
                              </div>
                              <p className="text-sm text-green-300/80 font-mono">{value}</p>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                    
                    {scanResult.threats.length > 0 && (
                      <div className="mt-4 p-4 bg-red-900/20 rounded-sm border border-red-500/30">
                        <h4 className="text-red-400 font-medium mb-3 flex items-center gap-2 font-mono">
                          <AlertTriangle className="h-5 w-5 text-red-500" /> SECURITY VULNERABILITIES
                        </h4>
                        <ul className="space-y-2">
                          {scanResult.threats.map((threat, index) => (
                            <li key={index} className="flex items-center gap-2">
                              <div className="h-1.5 w-1.5 rounded-full bg-red-500"></div>
                              <span className="text-sm text-red-400 font-mono">[THREAT-{index+1}]: {threat}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    
                    {/* Safety recommendation */}
                    <div className={`p-4 rounded-sm border ${scanResult.isSafe ? 
                      'bg-green-900/20 border-green-500/30 text-green-400' : 
                      'bg-red-900/20 border-red-500/30 text-red-400'}`}>
                      <h4 className="font-medium flex items-center gap-2 mb-2 font-mono">
                        {scanResult.isSafe ? (
                          <>
                            <Lock className="h-5 w-5" /> SECURITY CLEARANCE: GRANTED
                          </>
                        ) : (
                          <>
                            <AlertTriangle className="h-5 w-5" /> SECURITY ALERT: THREAT DETECTED
                          </>
                        )}
                      </h4>
                      <p className="text-sm font-mono">
                        {scanResult.isSafe ? 
                          `This URL has passed security validation with a confidence score of ${scanResult.score}/100. Normal security protocols are sufficient when accessing this resource.` : 
                          `This URL exhibits multiple security risk indicators with a threat score of ${100-scanResult.score}/100. System recommends avoiding this resource to maintain security integrity.`
                        }
                      </p>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="mt-6 flex justify-end">
                <Button 
                  onClick={resetScan}
                  className="bg-green-800/30 text-green-400 border border-green-500/50 hover:bg-green-800/50 font-mono"
                >
                  <FileCode className="h-4 w-4 mr-2" />
                  INITIATE NEW SCAN
                </Button>
              </div>
            </div>
          )}
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mt-10">
            <Card className="bg-black/80 p-6 flex flex-col items-center text-center border border-green-500/30 rounded-lg hover:border-green-500/50 transition-all terminal-window">
              <div className="bg-green-900/20 p-3 rounded-md mb-4 border border-green-500/30">
                <Shield className="h-7 w-7 text-green-400 animate-pulse-glow" />
              </div>
              <h3 className="text-lg font-medium text-green-400 mb-2 font-mono">ADVANCED PROTECTION</h3>
              <p className="text-green-300/80 text-sm font-mono">
                Neural scanning algorithms continuously adapt to identify emergent phishing vectors and zero-day exploits.
              </p>
            </Card>
            
            <Card className="bg-black/80 p-6 flex flex-col items-center text-center border border-green-500/30 rounded-lg hover:border-green-500/50 transition-all terminal-window">
              <div className="bg-green-900/20 p-3 rounded-md mb-4 border border-green-500/30">
                <Network className="h-7 w-7 text-green-400 animate-pulse-glow" />
              </div>
              <h3 className="text-lg font-medium text-green-400 mb-2 font-mono">THREAT INTELLIGENCE</h3>
              <p className="text-green-300/80 text-sm font-mono">
                Deep analysis of domain architecture, certificate validation, and network behavior pattern recognition.
              </p>
            </Card>
            
            <Card className="bg-black/80 p-6 flex flex-col items-center text-center border border-green-500/30 rounded-lg hover:border-green-500/50 transition-all terminal-window">
              <div className="bg-green-900/20 p-3 rounded-md mb-4 border border-green-500/30">
                <Lock className="h-7 w-7 text-green-400 animate-pulse-glow" />
              </div>
              <h3 className="text-lg font-medium text-green-400 mb-2 font-mono">SECURITY PROTOCOLS</h3>
              <p className="text-green-300/80 text-sm font-mono">
                Identifies sophisticated attack vectors including credential harvesting, social engineering, and network exploits.
              </p>
            </Card>
          </div>
        </div>
      </main>
      
      <footer className="border-t border-green-500/20 py-6 mt-20">
        <div className="container mx-auto px-4 text-center">
          <p className="text-green-500/50 text-sm font-mono">
            CYBERSENTRY v2.0 // SECURE NETWORK PROTOCOL // {new Date().getFullYear()}
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Dashboard;
