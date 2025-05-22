
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Search, Link as LinkIcon, AlertTriangle, LogOut, Check, Network, Lock, User, Terminal, Code, Database, FileCode, ExternalLink, ChevronRight, CheckCircle2, XCircle } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import { Card } from '@/components/ui/card';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { supabase } from "@/integrations/supabase/client";
import { useIsMobile } from '@/hooks/use-mobile';

const Dashboard = () => {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanResult, setScanResult] = useState<any>(null);
  const [user, setUser] = useState<any>(null);
  const [nameDialog, setNameDialog] = useState(false);
  const [fullName, setFullName] = useState('');
  const [userFullName, setUserFullName] = useState('');
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);
  const navigate = useNavigate();
  const isMobile = useIsMobile();
  
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
      toast.success('Welcome to PhishGuard!');
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
      toast.info('Initiating advanced security scan...');
      
      // Improved progress simulation for better UX
      const progressInterval = setInterval(() => {
        setScanProgress(prev => {
          // Make the progress more smooth and realistic
          const increment = Math.random() * 5 + (prev < 30 ? 5 : prev < 60 ? 3 : 1);
          const newProgress = prev + increment;
          return newProgress >= 95 ? 95 : newProgress;
        });
      }, 200);
      
      // Call our enhanced edge function for URL scanning
      const { data: result, error } = await supabase.functions.invoke('scan-url', {
        body: { url: formattedUrl },
      });
      
      if (error) throw error;
      
      setScanResult(result);
      
      // Complete progress
      clearInterval(progressInterval);
      setScanProgress(100);
      
      if (result.isSafe) {
        toast.success(`URL appears safe with score: ${result.overallScore}/100`);
      } else {
        toast.error(`Security threats detected! Score: ${result.overallScore}/100`);
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
    setShowTechnicalDetails(false);
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'bg-green-500 text-black';
    if (score >= 60) return 'bg-yellow-500 text-black';
    return 'bg-red-500 text-white';
  };
  
  const getScoreRingColor = (score: number) => {
    if (score >= 80) return '#22c55e';
    if (score >= 60) return '#eab308';
    return '#ef4444';
  };
  
  const getFactorStatusIcon = (status: string) => {
    if (status === 'Pass') {
      return <CheckCircle2 className="h-4 w-4 text-green-500" />;
    } else if (status === 'Warning') {
      return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
    } else {
      return <XCircle className="h-4 w-4 text-red-500" />;
    }
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
      <header className="border-b border-green-500/30 bg-black sticky top-0 z-30 digital-scan backdrop-blur-sm">
        <div className="container mx-auto py-4 px-4 flex justify-between items-center flex-wrap gap-2">
          <div className="flex items-center space-x-3">
            <Shield className="h-7 w-7 text-green-500 animate-pulse-glow" />
            <h1 className="text-xl md:text-2xl font-mono font-bold text-green-400 hacker-text">PHISHGUARD</h1>
          </div>
          
          <div className="flex items-center gap-4 flex-wrap">
            {/* Enhanced Highlighted Username Display */}
            <div className="flex items-center gap-2 bg-green-900/30 py-2 px-4 border-2 border-green-500 rounded-md shadow-lg shadow-green-900/20 pulse-highlight animate-pulse-subtle">
              <User className="h-5 w-5 text-green-500" />
              <span className="text-sm md:text-base text-green-300 font-mono font-bold">
                OPERATOR: <span className="text-green-400">{userFullName || user?.email?.split('@')[0]}</span>
              </span>
            </div>
            
            <Button 
              variant="outline" 
              onClick={handleLogout}
              className="text-green-400 border-green-500/50 hover:bg-green-500/10 flex items-center gap-2 font-mono shadow-lg shadow-green-900/10"
              size={isMobile ? "sm" : "default"}
            >
              <LogOut className="h-4 w-4" />
              <span>{isMobile ? '' : 'LOGOUT'}</span>
            </Button>
          </div>
        </div>
      </header>
      
      <main className="container mx-auto py-6 md:py-10 px-3 md:px-4">
        <div className="text-center mb-6 md:mb-12 relative">
          <div className="absolute inset-0 -z-10 bg-gradient-radial from-green-500/10 to-transparent rounded-xl"></div>
          <h1 className="text-3xl md:text-4xl font-bold mb-3 md:mb-4 text-green-400 hacker-text font-mono">
            <span className="terminal-text">URL SECURITY SCANNER</span>
          </h1>
          <p className="text-green-300 max-w-2xl mx-auto font-mono opacity-80 text-sm md:text-base px-2">
            [ENTER TARGET URL FOR ADVANCED SECURITY ANALYSIS]
            <br className="hidden md:block" />
            <span className="md:hidden">SCAN FOR MALICIOUS PATTERNS</span>
            <span className="hidden md:inline">SYSTEM WILL SCAN FOR MALICIOUS PATTERNS AND VULNERABILITIES</span>
          </p>
        </div>
        
        <div className="max-w-4xl mx-auto">
          <form onSubmit={handleScan} className="bg-black/90 p-4 md:p-6 mb-6 md:mb-8 border border-green-500/50 rounded-lg terminal-window relative overflow-hidden shadow-xl shadow-green-900/20">
            {/* Matrix rain effect */}
            <div className="absolute inset-0 pointer-events-none opacity-10 z-0">
              <div className="matrix-rain"></div>
            </div>
            
            {/* Scanner effect for when scanning */}
            {scanning && (
              <div className="absolute inset-0 overflow-hidden pointer-events-none z-10">
                <div className="w-full h-1 bg-gradient-to-r from-transparent via-green-500 to-transparent absolute" 
                     style={{ animation: 'scanner-sweep 1.5s ease-in-out infinite', top: `${Math.random() * 100}%` }}></div>
              </div>
            )}
            
            <div className="flex flex-col gap-4 relative z-10">
              <div className="relative">
                <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
                  <LinkIcon className="h-5 w-5 text-green-500" />
                </div>
                <Input
                  type="text"
                  placeholder="ENTER TARGET URL (e.g., example.com)"
                  className="pl-10 pr-4 bg-black/80 text-green-400 border-green-500/50 font-mono focus:border-green-400 focus:ring-green-400 placeholder:text-green-700/50 h-12 shadow-lg shadow-green-900/20"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  disabled={scanning}
                />
              </div>
              
              <Button 
                type="submit"
                disabled={scanning || !url}
                className="bg-green-600 hover:bg-green-700 text-black font-bold whitespace-nowrap flex items-center gap-2 transition-colors font-mono cyber-button h-12"
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
              <div className="mt-6 animate-fade-in">
                <div className="flex justify-between text-xs text-green-400 mb-2 font-mono">
                  <span className="flex items-center">
                    <div className="h-2 w-2 bg-green-500 rounded-full animate-pulse mr-2"></div>
                    SCANNING TARGET
                  </span>
                  <span>{Math.round(scanProgress)}%</span>
                </div>
                <Progress 
                  value={scanProgress} 
                  className="h-2.5 bg-green-950/80" 
                  indicatorClassName="bg-gradient-to-r from-green-600 to-green-400 shadow-glow" 
                />
                
                <div className="mt-6 bg-black/80 p-4 rounded-lg border border-green-500/30">
                  <h3 className="text-green-400 font-mono font-bold mb-4 text-lg flex items-center">
                    <Shield className="mr-2 h-5 w-5 text-green-500" />
                    SECURITY SCAN PROGRESS
                  </h3>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="border border-green-600/30 rounded p-3 bg-green-950/20">
                      <h4 className="text-green-400 font-mono text-sm mb-2">DOMAIN ANALYSIS</h4>
                      <div className="space-y-3">
                        <div>
                          <div className="flex justify-between mb-1 text-xs text-green-500">
                            <span>Domain Reputation</span>
                            <span>{Math.min(100, scanProgress * 1.2)}%</span>
                          </div>
                          <div className="h-1.5 bg-green-950/50 rounded-full overflow-hidden">
                            <div 
                              className="h-full bg-green-500 rounded-full transition-all duration-300" 
                              style={{ width: `${Math.min(100, scanProgress * 1.2)}%` }}
                            ></div>
                          </div>
                        </div>
                        
                        <div>
                          <div className="flex justify-between mb-1 text-xs text-green-500">
                            <span>URL Structure</span>
                            <span>{Math.min(100, scanProgress * 1.4)}%</span>
                          </div>
                          <div className="h-1.5 bg-green-950/50 rounded-full overflow-hidden">
                            <div 
                              className="h-full bg-green-500 rounded-full transition-all duration-300" 
                              style={{ width: `${Math.min(100, scanProgress * 1.4)}%` }}
                            ></div>
                          </div>
                        </div>
                      </div>
                    </div>
                    
                    <div className="border border-green-600/30 rounded p-3 bg-green-950/20">
                      <h4 className="text-green-400 font-mono text-sm mb-2">SECURITY ANALYSIS</h4>
                      <div className="space-y-3">
                        <div>
                          <div className="flex justify-between mb-1 text-xs text-green-500">
                            <span>SSL Certificate</span>
                            <span>{Math.min(100, scanProgress * 0.9)}%</span>
                          </div>
                          <div className="h-1.5 bg-green-950/50 rounded-full overflow-hidden">
                            <div 
                              className="h-full bg-green-500 rounded-full transition-all duration-300" 
                              style={{ width: `${Math.min(100, scanProgress * 0.9)}%` }}
                            ></div>
                          </div>
                        </div>
                        
                        <div>
                          <div className="flex justify-between mb-1 text-xs text-green-500">
                            <span>AI Analysis</span>
                            <span>{Math.min(100, scanProgress * 0.7)}%</span>
                          </div>
                          <div className="h-1.5 bg-green-950/50 rounded-full overflow-hidden">
                            <div 
                              className="h-full bg-green-500 rounded-full transition-all duration-300" 
                              style={{ width: `${Math.min(100, scanProgress * 0.7)}%` }}
                            ></div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  <div className="mt-3 font-mono text-xs text-green-500/70 h-16 overflow-hidden scanner-logs">
                    <div className="animate-slide-up">
                      {scanProgress > 10 && <p>[SYSTEM] Resolving domain name...</p>}
                      {scanProgress > 25 && <p>[SYSTEM] Checking SSL certificate status...</p>}
                      {scanProgress > 40 && <p>[SYSTEM] Analyzing URL structure for suspicious patterns...</p>}
                      {scanProgress > 55 && <p>[SYSTEM] Running AI model classification...</p>}
                      {scanProgress > 70 && <p>[SYSTEM] Calculating security score...</p>}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </form>
          
          {scanResult && (
            <div className="bg-black/90 p-4 md:p-6 mb-6 md:mb-8 rounded-lg border border-green-500/50 terminal-window animate-fade-in shadow-xl shadow-green-900/30">
              <div className="flex flex-col md:flex-row items-start gap-6 md:gap-8">
                {/* Security Score Circle */}
                <div className="relative h-32 w-32 md:h-40 md:w-40 flex-shrink-0 mx-auto md:mx-0">
                  <div className="absolute inset-0 grid-pattern rounded-full opacity-20"></div>
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
                      stroke={getScoreRingColor(scanResult.overallScore)} 
                      strokeWidth="10" 
                      strokeDasharray={`${scanResult.overallScore * 2.83} 283`} 
                      strokeLinecap="round"
                      className="animate-pulse-glow"
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center flex-col">
                    <span className="text-2xl md:text-4xl font-bold text-green-400 font-mono">{Math.round(scanResult.overallScore)}</span>
                    <span className="text-xs text-green-500/80 font-mono">SECURITY SCORE</span>
                  </div>
                </div>
                
                {/* Results Summary */}
                <div className="flex-1 space-y-4 md:space-y-6 w-full">
                  <div>
                    <div className="flex flex-col sm:flex-row sm:items-center gap-3 mb-3">
                      <h3 className="text-xl font-bold text-green-400 font-mono">SECURITY ASSESSMENT</h3>
                      {scanResult.isSafe ? (
                        <span className="bg-green-900/40 text-green-400 border border-green-500/50 px-3 py-1 rounded-sm text-sm font-mono flex items-center gap-1 w-fit">
                          <Check className="h-4 w-4" /> SECURE
                        </span>
                      ) : (
                        <span className="bg-red-900/40 text-red-400 border border-red-500/50 px-3 py-1 rounded-sm text-sm font-mono flex items-center gap-1 w-fit">
                          <AlertTriangle className="h-4 w-4" /> THREAT DETECTED
                        </span>
                      )}
                    </div>
                    
                    <div className="space-y-3">
                      <div className="flex items-start gap-2">
                        <LinkIcon className="h-5 w-5 text-green-500 mt-0.5" />
                        <div className="flex-1 overflow-hidden">
                          <span className="text-sm text-green-500/80 font-mono">TARGET URL:</span>
                          <div className="flex items-center gap-2 flex-wrap">
                            <p className="text-green-400 break-all font-mono text-sm">{scanResult.url}</p>
                            <a 
                              href={scanResult.url} 
                              target="_blank" 
                              rel="noopener noreferrer"
                              className="text-green-500 hover:text-green-400 transition-colors"
                            >
                              <ExternalLink className="h-4 w-4" />
                            </a>
                          </div>
                        </div>
                      </div>
                      
                      <div className="flex items-start gap-2">
                        <Shield className="h-5 w-5 text-green-500 mt-0.5" />
                        <div>
                          <span className="text-sm text-green-500/80 font-mono">RISK ASSESSMENT:</span>
                          <p className="text-green-400 font-mono">{scanResult.riskLevel}</p>
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  {/* Factor Results Grid */}
                  <div>
                    <h4 className="text-green-400 font-medium mb-3 flex items-center gap-2 font-mono">
                      <Database className="h-5 w-5 text-green-500" /> SECURITY FACTOR ANALYSIS
                    </h4>
                    
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      {scanResult.factorResults && Object.entries(scanResult.factorResults).map(([key, value]: [string, any]) => {
                        if (key === 'mlClassification') return null; // Skip ML classification as we show it separately
                        
                        const isWarning = value.status === 'Warning';
                        const isFail = value.status === 'Fail';
                        
                        return (
                          <div key={key} className={`p-3 rounded-sm border ${
                            isFail ? 'bg-red-900/20 border-red-500/30' : 
                            isWarning ? 'bg-yellow-900/20 border-yellow-500/30' : 
                            'bg-green-900/20 border-green-500/30'
                          } hover:bg-opacity-30 transition-colors`}>
                            <div className="flex justify-between items-center mb-1">
                              <p className="text-sm font-medium text-green-400 font-mono capitalize">
                                {key.replace(/([A-Z])/g, ' $1').replace(/^./, (str) => str.toUpperCase())}
                              </p>
                              <div className="flex items-center gap-1">
                                <span className="text-xs text-green-400/70">
                                  {value.score ? `${value.score}/100` : ''}
                                </span>
                                {getFactorStatusIcon(value.status)}
                              </div>
                            </div>
                            <p className="text-sm text-green-300/80 font-mono">{value.analysis}</p>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              </div>
              
              {/* ML Classification Section */}
              {scanResult.factorResults && scanResult.factorResults.mlClassification && (
                <div className="mt-6 p-4 bg-green-900/20 rounded-sm border border-green-500/30">
                  <h4 className="text-green-400 font-medium mb-3 flex items-center gap-2 font-mono">
                    <Network className="h-5 w-5 text-green-500" /> AI MODEL ANALYSIS
                  </h4>
                  
                  <div className="flex flex-col gap-3">
                    <div className="flex items-start gap-2">
                      <div className="h-2 w-2 bg-green-500 rounded-full mt-2"></div>
                      <div>
                        <p className="text-green-400 font-mono text-sm font-medium">
                          Prediction: <span className="text-green-300">{scanResult.factorResults.mlClassification.prediction}</span>
                        </p>
                      </div>
                    </div>
                    
                    <div className="flex items-start gap-2">
                      <div className="h-2 w-2 bg-green-500 rounded-full mt-2"></div>
                      <div>
                        <p className="text-green-400 font-mono text-sm font-medium">
                          Confidence: <span className="text-green-300">{scanResult.factorResults.mlClassification.mlConfidence}%</span>
                        </p>
                      </div>
                    </div>
                    
                    <div className="flex items-start gap-2">
                      <div className="h-2 w-2 bg-green-500 rounded-full mt-2"></div>
                      <div>
                        <p className="text-green-400 font-mono text-sm font-medium">
                          Analysis: <span className="text-green-300">{scanResult.factorResults.mlClassification.analysis}</span>
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}
              
              {/* Security Threats Section */}
              {scanResult.threats && scanResult.threats.length > 0 && (
                <div className="mt-6 p-4 bg-red-900/20 rounded-sm border border-red-500/30">
                  <h4 className="text-red-400 font-medium mb-3 flex items-center gap-2 font-mono">
                    <AlertTriangle className="h-5 w-5 text-red-500" /> SECURITY VULNERABILITIES
                  </h4>
                  <ul className="space-y-2">
                    {scanResult.threats.map((threat: string, index: number) => (
                      <li key={index} className="flex items-start gap-2">
                        <div className="h-1.5 w-1.5 rounded-full bg-red-500 mt-1.5"></div>
                        <span className="text-sm text-red-400 font-mono">[THREAT-{index+1}]: {threat}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              
              {/* Technical Details Toggle */}
              {scanResult.technicalDetails && (
                <div className="mt-6">
                  <button
                    onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
                    className="w-full flex items-center justify-between p-3 bg-green-900/20 rounded-sm border border-green-500/30 text-green-400 font-mono hover:bg-green-900/30 transition-colors"
                  >
                    <div className="flex items-center gap-2">
                      <Code className="h-5 w-5 text-green-500" />
                      <span className="font-medium">ADVANCED TECHNICAL DETAILS</span>
                    </div>
                    <ChevronRight className={`h-5 w-5 transition-transform ${showTechnicalDetails ? 'rotate-90' : ''}`} />
                  </button>
                  
                  {showTechnicalDetails && (
                    <div className="mt-3 p-4 bg-black/80 border border-green-500/30 rounded-sm font-mono text-xs text-green-300 overflow-x-auto">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {/* URL Details */}
                        <div>
                          <h5 className="text-green-400 font-medium mb-2">URL ANALYSIS</h5>
                          <ul className="space-y-2 text-green-300/80">
                            <li><span className="text-green-500">Protocol:</span> {scanResult.technicalDetails.url.protocol}</li>
                            <li><span className="text-green-500">Hostname:</span> {scanResult.technicalDetails.url.hostname}</li>
                            <li><span className="text-green-500">Path:</span> {scanResult.technicalDetails.url.pathname || '/'}</li>
                            <li><span className="text-green-500">Path Depth:</span> {scanResult.technicalDetails.url.pathDepth}</li>
                            <li><span className="text-green-500">Query String:</span> {scanResult.technicalDetails.url.queryString || 'None'}</li>
                            <li><span className="text-green-500">Fragment:</span> {scanResult.technicalDetails.url.fragment || 'None'}</li>
                            <li><span className="text-green-500">Port:</span> {scanResult.technicalDetails.url.port}</li>
                          </ul>
                        </div>
                        
                        {/* Domain Details */}
                        <div>
                          <h5 className="text-green-400 font-medium mb-2">DOMAIN ANALYSIS</h5>
                          <ul className="space-y-2 text-green-300/80">
                            <li><span className="text-green-500">Domain:</span> {scanResult.technicalDetails.domain.name}</li>
                            <li><span className="text-green-500">TLD:</span> {scanResult.technicalDetails.domain.tld}</li>
                            <li><span className="text-green-500">Subdomains:</span> {scanResult.technicalDetails.domain.subdomains}</li>
                            <li><span className="text-green-500">Length:</span> {scanResult.technicalDetails.domain.length} characters</li>
                            <li><span className="text-green-500">Has Numbers:</span> {scanResult.technicalDetails.domain.hasNumbers ? 'Yes' : 'No'}</li>
                            <li><span className="text-green-500">Has Dashes:</span> {scanResult.technicalDetails.domain.hasDashes ? 'Yes' : 'No'}</li>
                            <li><span className="text-green-500">Entropy:</span> {scanResult.technicalDetails.domain.entropy}</li>
                          </ul>
                        </div>
                        
                        {/* Risk Factors */}
                        <div className="md:col-span-2">
                          <h5 className="text-green-400 font-medium mb-2">RISK FACTORS</h5>
                          
                          {/* Suspicious Patterns */}
                          <div className="mb-3">
                            <h6 className="text-green-500 mb-1">SUSPICIOUS PATTERNS</h6>
                            {scanResult.technicalDetails.riskFactors.suspiciousPatterns.length > 0 ? (
                              <div className="flex flex-wrap gap-2">
                                {scanResult.technicalDetails.riskFactors.suspiciousPatterns.map((pattern: string, idx: number) => (
                                  <span key={idx} className="px-2 py-0.5 bg-red-900/30 border border-red-500/30 rounded text-xxs">
                                    {pattern}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span className="text-green-300/70">No suspicious patterns detected</span>
                            )}
                          </div>
                          
                          {/* High Risk Terms */}
                          <div className="mb-3">
                            <h6 className="text-green-500 mb-1">HIGH RISK TERMS</h6>
                            {Object.keys(scanResult.technicalDetails.riskFactors.highRiskTerms).length > 0 ? (
                              <div className="flex flex-wrap gap-2">
                                {Object.entries(scanResult.technicalDetails.riskFactors.highRiskTerms).map(([term, score]: [string, any], idx: number) => (
                                  <span key={idx} className="px-2 py-0.5 bg-red-900/30 border border-red-500/30 rounded text-xxs">
                                    {term}: {score}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span className="text-green-300/70">No high risk terms detected</span>
                            )}
                          </div>
                          
                          {/* Unusual Structure */}
                          <div className="mb-3">
                            <h6 className="text-green-500 mb-1">UNUSUAL STRUCTURE</h6>
                            {scanResult.technicalDetails.riskFactors.unusualStructure.length > 0 ? (
                              <ul className="list-disc pl-5 text-green-300/80">
                                {scanResult.technicalDetails.riskFactors.unusualStructure.map((issue: string, idx: number) => (
                                  <li key={idx}>{issue}</li>
                                ))}
                              </ul>
                            ) : (
                              <span className="text-green-300/70">No unusual structure detected</span>
                            )}
                          </div>
                          
                          {/* Encoded Content */}
                          <div>
                            <h6 className="text-green-500 mb-1">ENCODED CONTENT</h6>
                            {scanResult.technicalDetails.riskFactors.encodedContent.length > 0 ? (
                              <ul className="list-disc pl-5 text-green-300/80">
                                {scanResult.technicalDetails.riskFactors.encodedContent.map((encoding: string, idx: number) => (
                                  <li key={idx}>{encoding}</li>
                                ))}
                              </ul>
                            ) : (
                              <span className="text-green-300/70">No encoded content detected</span>
                            )}
                          </div>
                        </div>
                        
                        {/* ML Analysis */}
                        <div className="md:col-span-2">
                          <h5 className="text-green-400 font-medium mb-2">ML ANALYSIS</h5>
                          
                          {/* Feature Importance */}
                          <div className="mb-3">
                            <h6 className="text-green-500 mb-1">FEATURE IMPORTANCE</h6>
                            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                              {Object.entries(scanResult.technicalDetails.mlAnalysis.featureImportance).map(([feature, data]: [string, any]) => (
                                <div key={feature} className="bg-green-900/20 p-2 rounded border border-green-500/30">
                                  <div className="text-green-400">{feature.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}</div>
                                  <div className="text-xs text-green-300/80">
                                    <div>Weight: {data.weight}</div>
                                    <div>Score: {data.score}</div>
                                    <div>Contribution: {data.contribution.toFixed(2)}</div>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                          
                          {/* Confidence Intervals */}
                          <div className="mb-3">
                            <h6 className="text-green-500 mb-1">CONFIDENCE INTERVALS</h6>
                            <div className="bg-green-900/20 p-2 rounded border border-green-500/30 grid grid-cols-3">
                              <div>
                                <div className="text-green-400">Lower Bound</div>
                                <div className="text-green-300/80">{scanResult.technicalDetails.mlAnalysis.confidenceIntervals.lowerBound}</div>
                              </div>
                              <div>
                                <div className="text-green-400">Upper Bound</div>
                                <div className="text-green-300/80">{scanResult.technicalDetails.mlAnalysis.confidenceIntervals.upperBound}</div>
                              </div>
                              <div>
                                <div className="text-green-400">Confidence</div>
                                <div className="text-green-300/80">{scanResult.technicalDetails.mlAnalysis.confidenceIntervals.confidence}%</div>
                              </div>
                            </div>
                          </div>
                          
                          {/* Decision Explanation */}
                          <div>
                            <h6 className="text-green-500 mb-1">MODEL DECISION</h6>
                            <div className="bg-green-900/20 p-2 rounded border border-green-500/30">
                              <div className="grid grid-cols-2 gap-2">
                                <div>
                                  <div className="text-green-400">Decision</div>
                                  <div className="text-green-300/80">{scanResult.technicalDetails.mlAnalysis.modelDecision.decision}</div>
                                </div>
                                <div>
                                  <div className="text-green-400">Confidence Level</div>
                                  <div className="text-green-300/80">{scanResult.technicalDetails.mlAnalysis.modelDecision.confidenceLevel}</div>
                                </div>
                              </div>
                              <div className="mt-2">
                                <div className="text-green-400">Explanation</div>
                                <div className="text-green-300/80">{scanResult.technicalDetails.mlAnalysis.modelDecision.explanation}</div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
              
              {/* Safety recommendation */}
              <div className={`mt-6 p-4 rounded-sm border ${scanResult.isSafe ? 
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
                    `This URL has passed comprehensive security validation with a confidence score of ${scanResult.overallScore}/100. Standard security protocols are sufficient when accessing this resource.` : 
                    `This URL exhibits ${scanResult.threats.length} security risk indicators with a threat score of ${100-scanResult.overallScore}/100. System recommends avoiding this resource to maintain security integrity.`
                  }
                </p>
              </div>
              
              <div className="mt-5 flex justify-end">
                <Button 
                  onClick={resetScan}
                  className="bg-green-800/30 text-green-400 border border-green-500/50 hover:bg-green-800/50 font-mono"
                >
                  <FileCode className="h-4 w-4 mr-2" />
                  SCAN NEW URL
                </Button>
              </div>
            </div>
          )}
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-8">
            <Card className="bg-black/80 p-5 flex flex-col items-center text-center border border-green-500/30 rounded-lg hover:border-green-500/50 transition-all terminal-window shadow-lg shadow-green-900/20">
              <div className="bg-green-900/30 p-3 rounded-md mb-3 border border-green-500/30">
                <Shield className="h-6 w-6 text-green-400 animate-pulse-glow" />
              </div>
              <h3 className="text-lg font-medium text-green-400 mb-2 font-mono">PHISHING PROTECTION</h3>
              <p className="text-green-300/80 text-sm font-mono">
                Detect sophisticated phishing attempts targeting your personal information.
              </p>
            </Card>
            
            <Card className="bg-black/80 p-5 flex flex-col items-center text-center border border-green-500/30 rounded-lg hover:border-green-500/50 transition-all terminal-window shadow-lg shadow-green-900/20">
              <div className="bg-green-900/30 p-3 rounded-md mb-3 border border-green-500/30">
                <Network className="h-6 w-6 text-green-400 animate-pulse-glow" />
              </div>
              <h3 className="text-lg font-medium text-green-400 mb-2 font-mono">AI POWERED</h3>
              <p className="text-green-300/80 text-sm font-mono">
                Advanced machine learning algorithms detect even the most subtle phishing patterns.
              </p>
            </Card>
            
            <Card className="bg-black/80 p-5 flex flex-col items-center text-center border border-green-500/30 rounded-lg hover:border-green-500/50 transition-all terminal-window shadow-lg shadow-green-900/20">
              <div className="bg-green-900/30 p-3 rounded-md mb-3 border border-green-500/30">
                <Lock className="h-6 w-6 text-green-400 animate-pulse-glow" />
              </div>
              <h3 className="text-lg font-medium text-green-400 mb-2 font-mono">DETAILED REPORTS</h3>
              <p className="text-green-300/80 text-sm font-mono">
                Get comprehensive security analysis with actionable safety recommendations.
              </p>
            </Card>
          </div>
        </div>
      </main>
      
      <footer className="border-t border-green-500/20 py-4 mt-10 md:mt-20">
        <div className="container mx-auto px-4 text-center">
          <p className="text-green-500/50 text-sm font-mono">
            PHISHGUARD v1.0 // ADVANCED SECURITY PROTOCOL // {new Date().getFullYear()}
          </p>
        </div>
      </footer>
      
      {/* Add mobile-specific CSS */}
      <style>
        {`
        @media (max-width: 768px) {
          .matrix-bg {
            background-attachment: scroll;
          }
          
          .terminal-window {
            border-width: 1px;
          }
          
          .pulse-highlight {
            animation: pulse 2s infinite;
          }
          
          @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.4); }
            70% { box-shadow: 0 0 0 10px rgba(34, 197, 94, 0); }
            100% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0); }
          }
          
          .animate-pulse-subtle {
            animation: pulseSubtle 3s infinite;
          }
          
          @keyframes pulseSubtle {
            0% { opacity: 0.9; }
            50% { opacity: 1; }
            100% { opacity: 0.9; }
          }
          
          .text-xxs {
            font-size: 0.6rem;
          }
        }
        `}
      </style>
    </div>
  );
};

export default Dashboard;
