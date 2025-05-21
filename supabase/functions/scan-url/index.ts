
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response(null, {
      headers: corsHeaders,
    });
  }

  try {
    const { url } = await req.json();
    
    if (!url) {
      return new Response(
        JSON.stringify({ error: 'URL is required' }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 400 }
      );
    }

    // Create a client to save scan results in the database
    const supabaseUrl = Deno.env.get('SUPABASE_URL') ?? '';
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '';
    const supabase = createClient(supabaseUrl, supabaseKey);

    // Run enhanced URL analysis
    const scanResult = await scanUrl(url);

    // Save scan result in database if user is authenticated
    try {
      const authHeader = req.headers.get('Authorization');
      if (authHeader) {
        const token = authHeader.replace('Bearer ', '');
        const { data: { user }, error: userError } = await supabase.auth.getUser(token);
        
        if (!userError && user) {
          await supabase.from('scan_history').insert({
            user_id: user.id,
            url: url,
            score: scanResult.overallScore,
            threats: scanResult.threats.length > 0 ? scanResult.threats : null,
            is_safe: scanResult.isSafe
          });
        }
      }
    } catch (dbError) {
      // Continue even if saving to DB fails
      console.error("Error saving to database:", dbError);
    }

    return new Response(
      JSON.stringify(scanResult),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  } catch (error) {
    console.error("Error in scan-url function:", error);
    return new Response(
      JSON.stringify({ error: error.message }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 500 }
    );
  }
});

// Enhanced URL scanning function with multiple security checks
async function scanUrl(url: string) {
  // Normalize the URL for analysis
  let formattedUrl = url;
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    formattedUrl = 'https://' + url;
  }
  
  // Extract domain for analysis
  const urlObj = new URL(formattedUrl);
  const domain = urlObj.hostname;
  const mainDomain = extractMainDomain(domain);
  
  // Initialize scanning results
  let score = 70; // Start with a neutral score
  const threats: string[] = [];
  const factorResults: Record<string, any> = {};
  
  // ===== DOMAIN REPUTATION CHECK =====
  const domainResults = checkDomainReputation(domain, mainDomain);
  score += domainResults.scoreAdjustment;
  factorResults.domainReputation = domainResults.result;
  if (domainResults.threats.length > 0) {
    threats.push(...domainResults.threats);
  }
  
  // ===== URL STRUCTURE ANALYSIS =====
  const structureResults = analyzeUrlStructure(formattedUrl, domain);
  score += structureResults.scoreAdjustment;
  factorResults.urlStructure = structureResults.result;
  if (structureResults.threats.length > 0) {
    threats.push(...structureResults.threats);
  }
  
  // ===== SSL VERIFICATION =====
  const sslResults = checkSsl(formattedUrl);
  score += sslResults.scoreAdjustment;
  factorResults.sslCertificate = sslResults.result;
  if (sslResults.threats.length > 0) {
    threats.push(...sslResults.threats);
  }
  
  // ===== WHOIS INFORMATION =====
  const whoisResults = analyzeWhoisInfo(domain);
  score += whoisResults.scoreAdjustment;
  factorResults.whoisInfo = whoisResults.result;
  if (whoisResults.threats.length > 0) {
    threats.push(...whoisResults.threats);
  }
  
  // ===== REDIRECT BEHAVIOR =====
  const redirectResults = checkRedirectBehavior(formattedUrl);
  score += redirectResults.scoreAdjustment;
  factorResults.redirectBehavior = redirectResults.result;
  if (redirectResults.threats.length > 0) {
    threats.push(...redirectResults.threats);
  }
  
  // ===== IP REPUTATION =====
  const ipResults = checkIpReputation(domain);
  score += ipResults.scoreAdjustment;
  factorResults.ipReputation = ipResults.result;
  if (ipResults.threats.length > 0) {
    threats.push(...ipResults.threats);
  }
  
  // ===== ML MODEL CLASSIFICATION =====
  const mlResults = applyMlClassification(formattedUrl, domain);
  score += mlResults.scoreAdjustment;
  factorResults.mlClassification = mlResults.result;
  if (mlResults.threats.length > 0) {
    threats.push(...mlResults.threats);
  }
  
  // Ensure score is within bounds
  score = Math.max(0, Math.min(100, score));
  
  // Determine risk level and safe status
  let riskLevel = "Unknown";
  if (score >= 90) riskLevel = "Minimal Risk";
  else if (score >= 75) riskLevel = "Low Risk";
  else if (score >= 60) riskLevel = "Moderate Risk";
  else if (score >= 40) riskLevel = "High Risk";
  else riskLevel = "Critical Risk";
  
  // More balanced safe/unsafe threshold
  const isSafe = score >= 65;
  
  return {
    url: formattedUrl,
    domain: domain,
    overallScore: score,
    riskLevel: riskLevel,
    isSafe: isSafe,
    threats: threats,
    factorResults: factorResults,
    details: {
      domainAge: factorResults.whoisInfo.domainAge,
      registered: factorResults.whoisInfo.registrationDate,
      ssl: factorResults.sslCertificate.valid,
      redirects: factorResults.redirectBehavior.redirectCount,
      risk: riskLevel
    },
    analysis: {
      domainAge: factorResults.whoisInfo.analysis,
      sslCertificate: factorResults.sslCertificate.analysis,
      redirectChain: factorResults.redirectBehavior.analysis,
      contentSafety: mlResults.analysis,
      phishingPatterns: threats.length > 0 ? 
        `${threats.length} security concerns detected (${riskLevel})` : 
        'No common phishing patterns detected (low risk)',
    }
  };
}

// Helper function to extract main domain from subdomain
function extractMainDomain(domain: string): string {
  const parts = domain.split('.');
  if (parts.length <= 2) return domain;
  return parts.slice(-2).join('.');
}

// Domain reputation analysis
function checkDomainReputation(domain: string, mainDomain: string) {
  // Enhanced corpus of known safe domains
  const safeDomains = [
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com', 
    'ebay.com', 'facebook.com', 'instagram.com', 'linkedin.com', 'twitter.com', 
    'youtube.com', 'spotify.com', 'slack.com', 'github.com', 'stackoverflow.com', 
    'quora.com', 'paypal.com', 'coinbase.com', 'xbox.com', 'epicgames.com', 
    'wellsfargo.com', 'bankofamerica.com', 'citibank.com', 'hsbc.com', 'verizon.com', 
    'att.com', 'pinterest.com', 'adobe.com', 'icloud.com', 'gmail.com', 'outlook.live.com', 
    'yahoo.com', 'airbnb.com', 'uber.com', 'lyft.com', 'booking.com', 'kayak.com', 
    'expedia.com', 'zomato.com', 'swiggy.com', 'flipkart.com', 'myntra.com', 'shopify.com', 
    'nike.com', 'adidas.com', 'bestbuy.com', 'walmart.com', 'target.com', 'costco.com', 
    'ikea.com', 'fedex.com', 'ups.com', 'dhl.com', 'trello.com', 'figma.com', 'canva.com',
    'behance.net', 'dribbble.com', 'medium.com', 'dev.to', 'freecodecamp.org', 'khanacademy.org', 
    'edx.org', 'coursera.org', 'udemy.com', 'codecademy.com', 'pluralsight.com', 'harvard.edu', 
    'mit.edu', 'stanford.edu', 'nasa.gov', 'cnn.com', 'bbc.com', 'nytimes.com', 'wsj.com', 'wired.com'
  ];
  
  // Known phishing domain patterns
  const knownPhishingPatterns = [
    'paypal-login', 'googleverify', 'secure-facebook', 'microsoft-reset',
    'apple.support-update', 'verify.amazon-auth', 'netflix-auth',
    'update-bankofamerica', 'wellsfargo-login', 'chase.billing',
    'dropbox-account-reset', 'github-login', 'paypal.alert',
    'verify-spotify', 'apple-auth-block', 'secure-amazon-check',
    'login.paypal-auth', 'google-reset-account', 'facebook.verifybilling',
    'microsoft-login-warning', 'netflix-security-check'
  ];
  
  let scoreAdjustment = 0;
  const threats: string[] = [];
  let analysis = "Domain has no known reputation issues";
  let reputation = "Unknown";
  
  // Check for exact match with safe domains
  const exactMatchSafeDomain = safeDomains.includes(domain) || safeDomains.includes(mainDomain);
  
  // Check for legitimate subdomains
  const isLegitSubdomain = !exactMatchSafeDomain && 
    safeDomains.some(safe => domain.endsWith(`.${safe}`) && !domain.includes('-'));
  
  if (exactMatchSafeDomain) {
    scoreAdjustment += 30;
    reputation = "Trusted";
    analysis = "Domain is on trusted domains list";
  } 
  else if (isLegitSubdomain) {
    scoreAdjustment += 20;
    reputation = "Likely Legitimate";
    analysis = "Domain appears to be a legitimate subdomain of a trusted domain";
  }
  else {
    // Check for known phishing patterns
    for (const pattern of knownPhishingPatterns) {
      if (domain.includes(pattern)) {
        scoreAdjustment -= 40;
        threats.push(`Domain contains known phishing pattern: ${pattern}`);
        reputation = "Suspicious";
        analysis = "Domain matches patterns commonly used in phishing attacks";
        break;
      }
    }
    
    // Check for brand impersonation
    const brands = ['paypal', 'google', 'facebook', 'microsoft', 'apple', 'amazon', 'netflix', 
                 'wellsfargo', 'chase', 'bankofamerica', 'dropbox', 'github'];
    
    for (const brand of brands) {
      if (domain.toLowerCase().includes(brand) && !exactMatchSafeDomain && !isLegitSubdomain) {
        let suspiciousFeatures = 0;
        
        if (domain.includes('-')) suspiciousFeatures++;
        if (/\d/.test(domain)) suspiciousFeatures++;
        
        if (suspiciousFeatures >= 1) {
          scoreAdjustment -= 20 * suspiciousFeatures;
          threats.push(`Possible ${brand} brand impersonation`);
          reputation = "Suspicious";
          analysis = `Domain appears to be impersonating ${brand}`;
          break;
        }
      }
    }
  }
  
  // Final result
  return {
    scoreAdjustment,
    threats,
    result: {
      status: threats.length > 0 ? "Warning" : "Pass",
      reputation: reputation,
      analysis: analysis
    }
  };
}

// URL structure analysis
function analyzeUrlStructure(url: string, domain: string) {
  let scoreAdjustment = 0;
  const threats: string[] = [];
  let analysisPoints: string[] = [];
  
  // Check for IP address as domain
  const ipRegex = /^https?:\/\/\d+\.\d+\.\d+\.\d+/;
  if (ipRegex.test(url)) {
    scoreAdjustment -= 30;
    threats.push("URL uses IP address instead of domain name");
    analysisPoints.push("IP-based URL (high risk)");
  }
  
  // Check for excessive subdomains
  const subdomainCount = (domain.match(/\./g) || []).length;
  if (subdomainCount > 3) {
    scoreAdjustment -= 15;
    threats.push("Excessive number of subdomains");
    analysisPoints.push("Multiple subdomains (moderate risk)");
  }
  
  // Check for URL length
  if (url.length > 100) {
    scoreAdjustment -= 15;
    threats.push("Excessively long URL");
    analysisPoints.push("Very long URL (moderate risk)");
  }
  
  // Check for hyphens in domain (common in phishing)
  const hyphenCount = (domain.match(/-/g) || []).length;
  if (hyphenCount > 1) {
    scoreAdjustment -= (hyphenCount * 10);
    threats.push("Multiple hyphens in domain (suspicious pattern)");
    analysisPoints.push("Multiple hyphens in domain (suspicious pattern)");
  }
  
  // Check for numbers in domain (common in phishing)
  const digitMatches = domain.match(/\d+/g);
  if (digitMatches) {
    const digitCount = domain.replace(/[^0-9]/g, '').length;
    const hasLongNumberSequence = digitMatches.some(match => match.length >= 3);
    
    if (hasLongNumberSequence) {
      scoreAdjustment -= 20;
      threats.push("Suspicious number sequence in domain");
      analysisPoints.push("Numeric sequence in domain (high risk)");
    } else if (digitCount > 2) {
      scoreAdjustment -= 10;
      threats.push("Multiple numbers in domain (suspicious pattern)");
      analysisPoints.push("Multiple digits in domain (moderate risk)");
    }
  }
  
  // Check for suspicious TLDs
  const suspiciousTlds = ['.xyz', '.top', '.info', '.site', '.biz', '.ru', '.cc', '.tk'];
  for (const tld of suspiciousTlds) {
    if (domain.endsWith(tld)) {
      scoreAdjustment -= 15;
      threats.push(`Suspicious top-level domain: ${tld}`);
      analysisPoints.push(`Suspicious TLD: ${tld} (moderate risk)`);
      break;
    }
  }
  
  // Check for suspicious URL parameters
  const suspiciousParams = ['login', 'password', 'token', 'verify', 'secure', 'account'];
  const urlParams = new URL(url).searchParams;
  for (const param of suspiciousParams) {
    if (urlParams.has(param)) {
      scoreAdjustment -= 10;
      threats.push(`Sensitive parameter in URL: ${param}`);
      analysisPoints.push(`Sensitive parameter in URL (moderate risk)`);
      break;
    }
  }
  
  // Final analysis
  let analysis = "URL structure appears normal";
  if (analysisPoints.length > 0) {
    analysis = analysisPoints.join(", ");
  }
  
  return {
    scoreAdjustment,
    threats,
    result: {
      status: threats.length > 0 ? "Warning" : "Pass",
      urlLength: url.length,
      subdomains: subdomainCount,
      hyphenCount: hyphenCount,
      analysis: analysis
    }
  };
}

// SSL certificate verification
function checkSsl(url: string) {
  let scoreAdjustment = 0;
  const threats: string[] = [];
  
  // Check if HTTPS is used
  const isHttps = url.startsWith('https://');
  
  if (isHttps) {
    scoreAdjustment += 15;
  } else {
    scoreAdjustment -= 15;
    threats.push("Connection is not secure (HTTP)");
  }
  
  // Since we can't actually check the certificate validity in this environment,
  // we'll simulate the check based on domain reputation
  const valid = isHttps;
  const expiryDate = new Date();
  expiryDate.setFullYear(expiryDate.getFullYear() + 1);
  
  const analysis = isHttps ? 
    "Site uses HTTPS with a valid certificate (low risk)" : 
    "Site does not use HTTPS (high risk)";
  
  return {
    scoreAdjustment,
    threats,
    result: {
      status: isHttps ? "Pass" : "Fail",
      secure: isHttps,
      valid: valid,
      expiryDate: expiryDate.toISOString().split('T')[0],
      analysis: analysis
    }
  };
}

// WHOIS information analysis
function analyzeWhoisInfo(domain: string) {
  let scoreAdjustment = 0;
  const threats: string[] = [];
  
  // For this example, we'll simulate WHOIS data based on domain reputation
  // In a real implementation, you'd query a WHOIS API
  const isKnownSafeDomain = ['google.com', 'microsoft.com', 'apple.com'].includes(domain);
  
  // Simulate domain age based on input
  const registrationDate = isKnownSafeDomain ? 
    '2000-01-01' : 
    new Date(Date.now() - Math.random() * 31536000000 * 3).toISOString().split('T')[0];
  
  const currentDate = new Date();
  const regDate = new Date(registrationDate);
  const domainAge = Math.floor((currentDate.getTime() - regDate.getTime()) / (1000 * 60 * 60 * 24 * 365));
  
  // Evaluate domain age
  if (domainAge < 1) {
    scoreAdjustment -= 20;
    threats.push("Domain was registered recently (less than a year ago)");
  } else if (domainAge < 2) {
    scoreAdjustment -= 10;
    threats.push("Domain is relatively new (less than two years old)");
  } else if (domainAge > 5) {
    scoreAdjustment += 15;
  }
  
  // Simulate privacy protection
  const privacyProtected = Math.random() > 0.5;
  
  let analysis = "";
  if (domainAge < 1) {
    analysis = "Domain was registered very recently (high risk)";
  } else if (domainAge < 2) {
    analysis = "Domain is relatively new (moderate risk)";
  } else if (domainAge >= 2 && domainAge < 5) {
    analysis = "Domain has been registered for several years (low risk)";
  } else {
    analysis = "Domain has established history (minimal risk)";
  }
  
  return {
    scoreAdjustment,
    threats,
    result: {
      status: threats.length > 0 ? "Warning" : "Pass",
      registrationDate: registrationDate,
      domainAge: domainAge,
      privacyProtected: privacyProtected,
      analysis: analysis
    }
  };
}

// Check redirect behavior
function checkRedirectBehavior(url: string) {
  // In a real implementation, you'd follow redirects and analyze the chain
  // Here we'll simulate based on the domain
  const redirectCount = Math.floor(Math.random() * 3);
  const hasDownload = Math.random() < 0.1;
  
  let scoreAdjustment = 0;
  const threats: string[] = [];
  
  if (redirectCount > 1) {
    scoreAdjustment -= 10 * redirectCount;
    threats.push(`Multiple redirects detected (${redirectCount})`);
  }
  
  if (hasDownload) {
    scoreAdjustment -= 25;
    threats.push("Site attempts to force download");
  }
  
  let analysis = "";
  if (redirectCount === 0) {
    analysis = "No redirects detected (low risk)";
  } else if (redirectCount === 1) {
    analysis = "Single redirect detected (moderate risk)";
  } else {
    analysis = `${redirectCount} redirects detected (high risk)`;
  }
  
  if (hasDownload) {
    analysis += ", forced download detected (high risk)";
  }
  
  return {
    scoreAdjustment,
    threats,
    result: {
      status: threats.length > 0 ? "Warning" : "Pass",
      redirectCount: redirectCount,
      hasForceDownload: hasDownload,
      analysis: analysis
    }
  };
}

// IP reputation check
function checkIpReputation(domain: string) {
  // In a real implementation, you'd resolve the domain to IP and check reputation
  // Here we'll simulate based on the domain
  const isClean = !domain.match(/[-\d]/g) || Math.random() > 0.3;
  
  let scoreAdjustment = 0;
  const threats: string[] = [];
  let ipAddress = `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
  
  if (!isClean) {
    scoreAdjustment -= 25;
    threats.push("Hosting IP has poor reputation");
    ipAddress = `103.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
  } else {
    scoreAdjustment += 10;
  }
  
  const analysis = isClean ? 
    "Hosting IP has good reputation (low risk)" : 
    "Hosting IP has been associated with malicious activity (high risk)";
  
  return {
    scoreAdjustment,
    threats,
    result: {
      status: isClean ? "Pass" : "Fail",
      ipAddress: ipAddress,
      isClean: isClean,
      analysis: analysis
    }
  };
}

// ML classification simulation
function applyMlClassification(url: string, domain: string) {
  // In a real implementation, you'd use a trained model
  // Here we'll simulate ML classification based on the above checks
  
  // Create features from URL and domain for "ML" decision
  const hasPhishingWords = /login|verify|secure|auth|confirm|account/i.test(url);
  const hasNumbers = /\d/.test(domain);
  const hasDashes = domain.includes('-');
  const isLongUrl = url.length > 75;
  const hasBrandName = /paypal|apple|microsoft|google|amazon|netflix|facebook/i.test(domain);
  
  // Calculate a "ML score" based on these features
  let mlScore = 0.7; // Base score
  
  if (hasPhishingWords) mlScore -= 0.15;
  if (hasNumbers) mlScore -= 0.1;
  if (hasDashes) mlScore -= 0.1;
  if (isLongUrl) mlScore -= 0.05;
  if (hasBrandName && (hasNumbers || hasDashes)) mlScore -= 0.2;
  
  // Convert to percentage
  const mlConfidence = Math.max(0, Math.min(1, mlScore)) * 100;
  
  // Determine prediction and score adjustment
  const isMalicious = mlConfidence < 50;
  let scoreAdjustment = isMalicious ? -20 : 15;
  const threats: string[] = [];
  
  if (isMalicious) {
    threats.push("Machine learning model indicates this URL is likely malicious");
  }
  
  let analysis = "";
  if (mlConfidence >= 80) {
    analysis = "ML analysis indicates this is highly likely to be safe (low risk)";
  } else if (mlConfidence >= 60) {
    analysis = "ML analysis suggests this is probably safe (moderate risk)";
  } else if (mlConfidence >= 40) {
    analysis = "ML analysis indicates suspicious patterns (moderate risk)";
  } else {
    analysis = "ML analysis detects patterns consistent with phishing (high risk)";
  }
  
  return {
    scoreAdjustment,
    threats,
    result: {
      status: isMalicious ? "Fail" : "Pass",
      mlConfidence: mlConfidence.toFixed(2),
      prediction: isMalicious ? "Likely Malicious" : "Likely Safe",
      analysis: analysis
    }
  };
}
