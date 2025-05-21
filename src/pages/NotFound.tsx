
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Shield, AlertTriangle, Terminal } from 'lucide-react';

const NotFound = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-black matrix-bg">
      <div className="absolute inset-0 opacity-10 pointer-events-none">
        <div className="matrix-rain"></div>
      </div>
      
      <div className="text-center px-4 max-w-md">
        <Shield className="h-16 w-16 text-green-500 animate-pulse-glow mx-auto mb-6" />
        
        <div className="terminal-window p-6 mb-8">
          <div className="mb-6 flex items-center justify-center gap-2">
            <AlertTriangle className="h-8 w-8 text-red-500" />
            <h1 className="text-3xl font-bold text-green-400 font-mono animate-glitch">ERROR 404</h1>
          </div>
          
          <div className="p-4 border border-green-500/30 bg-black/60 rounded mb-6">
            <div className="flex items-start gap-2 mb-2">
              <Terminal className="h-5 w-5 text-green-500 mt-0.5 flex-shrink-0" />
              <div className="text-left">
                <p className="text-green-400 font-mono text-sm mb-1">
                  [SYSTEM]: Resource not found
                </p>
                <p className="text-green-500/70 font-mono text-xs">
                  The requested resource location has been moved, corrupted, or does not exist in the system.
                </p>
              </div>
            </div>
          </div>
          
          <div className="font-mono text-green-400 text-sm mb-8">
            <div className="mb-2 text-left">&gt; Initiating recovery protocol...</div>
            <div className="mb-2 text-left">&gt; Recovery protocol ready.</div>
            <div className="text-left animate-blink">&gt; Awaiting operator command_</div>
          </div>
          
          <div className="space-y-3">
            <Button
              onClick={() => navigate('/')}
              className="w-full cyber-button bg-green-600 hover:bg-green-700 text-black font-bold font-mono"
            >
              RETURN TO MAIN TERMINAL
            </Button>
            
            <Button
              onClick={() => window.location.reload()}
              variant="outline"
              className="w-full border border-green-500/30 text-green-400 hover:bg-green-900/20 font-mono"
            >
              RELOAD SYSTEM
            </Button>
          </div>
        </div>
        
        <div className="text-green-500/50 text-sm font-mono animate-pulse">
          CYBERSENTRY v2.1.0 // ERROR PROTOCOL ENGAGED
        </div>
      </div>
      
      {/* Code-like animation at the bottom */}
      <div className="fixed bottom-0 left-0 right-0 h-16 overflow-hidden pointer-events-none">
        <div className="text-red-500/30 text-xs font-mono whitespace-nowrap animate-scroll">
          {Array(50).fill(0).map((_, i) => (
            <span key={i} className="mr-4">
              ERROR_{Math.random().toString(36).substring(2, 10)}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
};

export default NotFound;
