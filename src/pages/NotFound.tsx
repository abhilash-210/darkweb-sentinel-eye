
import { useLocation } from "react-router-dom";
import { useEffect } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";

const NotFound = () => {
  const location = useLocation();

  useEffect(() => {
    console.error(
      "404 Error: User attempted to access non-existent route:",
      location.pathname
    );
  }, [location.pathname]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-cyber-dark p-4">
      <div className="absolute inset-0 network-lines opacity-20"></div>
      
      <div className="cyber-card w-full max-w-md p-8 text-center">
        <div className="flex justify-center mb-6">
          <AlertTriangle className="h-16 w-16 text-cyber-warning" />
        </div>
        
        <h1 className="text-5xl font-bold mb-2 text-white">404</h1>
        <p className="text-xl text-cyber-accent mb-6">Secure Zone Breach</p>
        <p className="text-gray-400 mb-8">
          The location you're attempting to access does not exist or has been moved to a different server.
        </p>
        
        <Link to="/">
          <Button className="cyber-button flex items-center gap-2 mx-auto">
            <ArrowLeft className="h-4 w-4" />
            <span>Return to Secure Zone</span>
          </Button>
        </Link>
      </div>
    </div>
  );
};

export default NotFound;
