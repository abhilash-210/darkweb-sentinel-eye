
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Search, Link as LinkIcon, AlertTriangle, LogOut, Check } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import { Card } from '@/components/ui/card';

// Mock phishing detection algorithm
// In a real app, you would call an API to check the URL
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
      // Simple heuristic for demo purposes
      const domain = url.replace(/^https?:\/\//, '').split('/')[0];
      let score = 0;
      const threats: string[] = [];
      
      // Domains that are considered safe
      const safeDomains = [
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 
        'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com'
      ];
      
      // Check for safe domains
      if (safeDomains.some(safe => domain.includes(safe))) {
        score = 95;
      } else {
        // Random score for demo
        score = Math.floor(Math.random() * 100);
        
        // Add fake threats based on score
        if (score < 30) {
          threats.push('Suspicious domain registration');
          threats.push('Known phishing patterns');
          threats.push('Missing SSL certificate');
        } else if (score < 60) {
          threats.push('Recently registered domain');
          if (score < 45) threats.push('Redirect chain detected');
        } else if (score < 80) {
          if (score < 70) threats.push('Unusual URL structure');
        }
      }

      resolve({
        score,
        threats,
        isSafe: score >= 70,
        details: {
          domain,
          registered: '2023-04-15',
          ssl: score > 40,
          redirects: score < 50 ? 2 : 0,
        }
      });
    }, 1500);
  });
};

const Dashboard = () => {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ReturnType<typeof analyzeUrl> extends Promise<infer T> ? T | null : never>(null);
  const navigate = useNavigate();
  
  // Check if user is logged in
  useEffect(() => {
    const token = localStorage.getItem('cyber-auth-token');
    if (!token) {
      navigate('/login');
    }
  }, [navigate]);
  
  const handleLogout = () => {
    localStorage.removeItem('cyber-auth-token');
    toast.success('Logged out successfully');
    navigate('/login');
  };
  
  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!url) {
      toast.error('Please enter a URL to scan');
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
      
      // Call our mock analysis function
      const result = await analyzeUrl(formattedUrl);
      setScanResult(result);
      
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
  
  return (
    <div className="min-h-screen bg-cyber-dark">
      <div className="absolute inset-0 network-lines opacity-20"></div>
      
      {/* Header */}
      <header className="border-b border-cyber-accent/20 bg-cyber-secondary/40 backdrop-blur-sm">
        <div className="container mx-auto py-4 px-4 flex justify-between items-center">
          <div className="flex items-center space-x-2">
            <Shield className="h-6 w-6 text-cyber-accent" />
            <h1 className="text-xl font-bold text-white">PhishGuard</h1>
          </div>
          
          <Button 
            variant="ghost" 
            onClick={handleLogout}
            className="text-gray-400 hover:text-white hover:bg-cyber-secondary flex items-center gap-2"
          >
            <LogOut className="h-4 w-4" />
            <span>Logout</span>
          </Button>
        </div>
      </header>
      
      <main className="container mx-auto py-10 px-4">
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold mb-4 text-white">
            <span className="text-cyber-accent">Phishing</span> Link Detector
          </h1>
          <p className="text-gray-400 max-w-2xl mx-auto">
            Enter any suspicious URL to analyze it for potential phishing threats.
            Our advanced AI will scan for common attack patterns and security issues.
          </p>
        </div>
        
        <div className="max-w-3xl mx-auto">
          <form onSubmit={handleScan} className="cyber-card p-6 mb-8">
            <div className="flex flex-col md:flex-row gap-4">
              <div className="flex-1">
                <Input
                  type="text"
                  placeholder="Enter URL to scan (e.g., https://example.com)"
                  className="cyber-input w-full"
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
            <div className="cyber-card p-6 mb-8 animate-fade-in">
              <div className="flex flex-col md:flex-row items-center gap-8">
                <div className="score-gauge glow-effect">
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
                        <div className="bg-cyber-dark/60 p-2 rounded">
                          <p className="text-xs text-gray-500">Domain</p>
                          <p className="text-sm text-white">{scanResult.details.domain}</p>
                        </div>
                        <div className="bg-cyber-dark/60 p-2 rounded">
                          <p className="text-xs text-gray-500">Registration</p>
                          <p className="text-sm text-white">{scanResult.details.registered}</p>
                        </div>
                        <div className="bg-cyber-dark/60 p-2 rounded">
                          <p className="text-xs text-gray-500">SSL Security</p>
                          <p className={`text-sm ${scanResult.details.ssl ? 'text-cyber-success' : 'text-cyber-danger'}`}>
                            {scanResult.details.ssl ? 'Secure (HTTPS)' : 'Not Secure'}
                          </p>
                        </div>
                        <div className="bg-cyber-dark/60 p-2 rounded">
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
                            <li key={index} className="bg-cyber-danger/10 text-cyber-danger text-sm p-2 rounded flex items-center gap-2">
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
            <Card className="cyber-card p-5 flex flex-col items-center text-center">
              <div className="bg-cyber-accent/10 p-3 rounded-full mb-4">
                <Shield className="h-7 w-7 text-cyber-accent" />
              </div>
              <h3 className="text-lg font-medium text-white mb-2">Real-time Protection</h3>
              <p className="text-gray-400 text-sm">
                Our advanced AI constantly updates to detect the latest phishing techniques and threats.
              </p>
            </Card>
            
            <Card className="cyber-card p-5 flex flex-col items-center text-center">
              <div className="bg-cyber-purple/10 p-3 rounded-full mb-4">
                <LinkIcon className="h-7 w-7 text-cyber-purple" />
              </div>
              <h3 className="text-lg font-medium text-white mb-2">URL Analysis</h3>
              <p className="text-gray-400 text-sm">
                Deep scanning of URLs for suspicious patterns, domain age, and security certificates.
              </p>
            </Card>
            
            <Card className="cyber-card p-5 flex flex-col items-center text-center">
              <div className="bg-cyber-warning/10 p-3 rounded-full mb-4">
                <AlertTriangle className="h-7 w-7 text-cyber-warning" />
              </div>
              <h3 className="text-lg font-medium text-white mb-2">Threat Detection</h3>
              <p className="text-gray-400 text-sm">
                Identifies potential threats including fake websites, credential theft attempts, and more.
              </p>
            </Card>
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
