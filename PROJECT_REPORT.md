
# CyberSentry - Advanced URL Security Analysis

![CyberSentry](https://img.shields.io/badge/CyberSentry-Network%20Security-brightgreen)

## 🔒 Project Overview

CyberSentry is a cutting-edge cybersecurity tool designed to detect and analyze potentially malicious URLs using advanced pattern recognition algorithms. The application features a sophisticated neural scanning engine that evaluates multiple security vectors to determine whether a URL is potentially dangerous or safe.

With its distinctive cyberpunk-inspired interface featuring a matrix-style black and green theme, CyberSentry delivers a unique user experience while providing enterprise-level security analysis. The tool helps users protect themselves against phishing attempts, credential harvesting, and other web-based attacks.

## 🛡️ Key Features

### Advanced Security Analysis
- **Neural URL Scanning**: Multi-layered analysis with pattern recognition to identify malicious URLs
- **Comprehensive Threat Detection**: Identifies multiple threat vectors including phishing, domain spoofing, and suspicious redirects
- **Domain Intelligence**: Real-time analysis of domain age, registration details, and reputation
- **SSL Certificate Verification**: Certificate validation and security protocol assessment
- **Visual Security Score**: Intuitive 0-100 security rating with detailed breakdown

### Cyberpunk User Experience
- **Matrix-Inspired Interface**: Immersive dark theme with terminal-style components and animations
- **Hacker Text Formatting**: Monospace font with distinctive green glow effects
- **Real-time Scan Visualization**: Dynamic scanning animations with code-like visual feedback
- **Security Clearance System**: User authentication with operator profiles
- **Terminal-Style Windows**: Command-line aesthetic for all interface components

### Technical Security
- **Pattern Recognition Algorithm**: Machine learning-like approach to URL threat assessment
- **Known Threat Database**: Built-in database of malicious URL patterns and safe domains
- **Multi-Factor Analysis**: Security assessment based on multiple risk indicators
- **Educational Insights**: Detailed explanations of detected security threats
- **Scan History**: Track and review previous URL scans

## 🔧 Technology Stack

### Frontend
- **React**: Component-based UI architecture with hooks for state management
- **TypeScript**: Type-safe code with full static typing
- **Tailwind CSS**: Utility-first CSS framework with custom cyberpunk styling
- **Shadcn UI**: Enhanced UI components with consistent design language
- **React Router**: Client-side routing between application pages
- **React Query**: Efficient data fetching and state management
- **Lucide Icons**: Scalable vector icons for the interface

### Backend & Authentication
- **Supabase**: Backend-as-a-Service for authentication and data storage
- **PostgreSQL**: Relational database for user data and scan history
- **JWT Authentication**: Secure token-based authentication system
- **Row Level Security**: Database-level security for data protection

### Security Features
- **Enhanced URL Analysis Algorithm**: Custom analysis based on known phishing patterns 
- **Domain Pattern Recognition**: Detection of suspicious domain patterns and spoofing attempts
- **Phishing Signature Detection**: Pattern matching against common phishing techniques
- **Risk Scoring System**: Sophisticated risk assessment based on multiple factors

## 📊 How It Works

1. **User Authentication**: Secure login/registration system with email verification
2. **Operator Profile**: Collection of user's full name for personalized experience
3. **URL Submission**: Users input a URL for security analysis
4. **Multi-Vector Scanning**: The system performs comprehensive security checks:
   - Domain pattern analysis
   - Phishing keyword detection
   - SSL certificate verification
   - Brand impersonation assessment
   - TLD reputation evaluation
   - Domain age estimation
5. **Security Report**: Detailed analysis with:
   - Overall security score (0-100)
   - Identified threats and vulnerabilities
   - Risk assessment and categorization
   - Technical details about potential issues
   - Recommendations for user action

## 🔍 URL Analysis Methodology

The URL scanning algorithm employs a multi-factor approach:

1. **Domain Validation**: Checks against database of known safe and malicious domains
2. **Pattern Recognition**: Analyzes domain structure for suspicious patterns:
   - Multiple hyphens or numbers
   - Brand names with numerical additions
   - Unusual TLDs (.xyz, .top, .site, etc.)
   - Excessive length
3. **Keyword Analysis**: Detects common phishing keywords like "login," "verify," "secure," etc.
4. **Brand Impersonation Detection**: Identifies attempts to mimic popular brands
5. **Protocol Assessment**: Evaluates HTTP vs. HTTPS security
6. **Score Calculation**: Comprehensive weighting of all factors to generate risk score

## 📱 Interface Components

- **Login/Register**: Secure authentication screens with cyberpunk aesthetic
- **Profile Setup**: Operator identification for system access
- **Dashboard**: Primary interface for URL scanning with real-time visualization
- **Scan Results**: Comprehensive security report with visual indicators
- **Matrix Background**: Dynamic code-rain animation effects
- **Terminal-Style Components**: Command-line aesthetic throughout the application

## 🔐 Security Considerations

- All URL scanning is performed client-side with no external API dependencies
- Authentication uses industry-standard JWT approach
- Minimal user data collection (email and name only)
- Educational components explain the nature of detected threats
- Strong password requirements enforce good security practices

## 👨‍💻 Installation & Setup

### Prerequisites
- Node.js (v14.0 or higher)
- npm or yarn

### Installation Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cybersentry.git
   cd cybersentry
   ```

2. Install dependencies:
   ```bash
   npm install
   # or
   yarn install
   ```

3. Set up Supabase:
   - Create a Supabase project
   - Configure authentication
   - Create necessary database tables (profiles, scan_history)
   - Set up environment variables

4. Start the development server:
   ```bash
   npm run dev
   # or
   yarn dev
   ```

5. Open your browser and navigate to `http://localhost:5173`

## 🚀 Future Enhancements

- **Browser Extension**: One-click URL analysis from any webpage
- **API Access**: Allow developers to integrate the scanning capabilities
- **Enhanced ML Model**: Machine learning to improve detection accuracy
- **Batch URL Processing**: Scan multiple URLs simultaneously
- **PDF Report Generation**: Downloadable detailed security reports
- **Team Collaboration**: Share scan results with team members
- **Custom Rules Engine**: Allow users to define custom security rules
- **Dark Web Monitoring**: Check if domains are associated with dark web activities

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- User interface components by [shadcn/ui](https://ui.shadcn.com/)
- Icons by [Lucide](https://lucide.dev/)
- Authentication provided by [Supabase](https://supabase.io/)
- Developed with React and TypeScript

---

© 2025 CyberSentry | Advanced URL Security Analysis Platform

