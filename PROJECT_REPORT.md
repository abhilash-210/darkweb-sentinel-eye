
# CyberSentry - Advanced URL Security Analysis

![CyberSentry](https://img.shields.io/badge/CyberSentry-Cyber%20Security-brightgreen)

## 🔒 Project Overview

CyberSentry is an advanced cybersecurity tool designed to detect and analyze potential phishing links and malicious URLs. With its sophisticated scanning algorithms and user-friendly interface, it helps users protect themselves against online threats, phishing attempts, and malicious websites.

The application features a sleek, hacker-inspired interface with a green and black color scheme, providing real-time analysis of URLs while delivering a unique, engaging user experience.

## 🛡️ Key Features

### Security Analysis
- **Deep URL Scanning**: Multi-layered analysis of URLs to detect phishing attempts
- **Threat Detection**: Identifies multiple security risks including phishing, malware, and suspicious redirects
- **Domain Intelligence**: Provides information about domain age, registration details, and hosting infrastructure
- **SSL Certificate Verification**: Checks for proper SSL implementation and certificate validity
- **Visual Security Score**: Easy-to-understand safety rating from 0-100

### User Experience
- **Secure Authentication**: Email/password authentication with proper security measures
- **Profile System**: User profiles with name customization
- **Hacker-Themed UI**: Unique terminal-inspired interface with animation effects
- **Real-time Scan Visualization**: Visual feedback during the scanning process
- **Responsive Design**: Fully functional across all device sizes

### Technical Security
- **Input Sanitization**: Protection against XSS and injection attacks
- **Secure API Calls**: Encrypted communication with backend services
- **User Data Protection**: Minimal data collection with strong encryption
- **Educational Resources**: Tips for identifying phishing attempts

## 🔧 Technology Stack

### Frontend
- **React**: Component-based UI architecture
- **TypeScript**: Type-safe code to prevent runtime errors
- **Tailwind CSS**: Custom-styled components with cyber theme
- **Shadcn UI**: Enhanced UI components with consistent design
- **React Router**: Seamless navigation between application pages
- **React Query**: Efficient data fetching and state management
- **Lucide Icons**: Scalable vector icons

### Backend & Authentication
- **Supabase**: Backend-as-a-Service for authentication and data storage
- **PostgreSQL**: Secure database for user data and scan history
- **Row Level Security (RLS)**: Data access control at the database level
- **JWT Authentication**: Secure token-based authentication

### Security Features
- **URL Analysis Algorithms**: Custom algorithms for URL threat detection
- **Domain Analysis**: Domain age and reputation checking
- **Phishing Detection**: Pattern recognition for common phishing techniques
- **Malicious Script Detection**: Scanning for harmful JavaScript and other code

## 📊 How It Works

1. **User Authentication**: Secure login/registration system with email verification
2. **User Profile**: Collection of user's full name for personalized experience
3. **URL Submission**: Users input a URL they want to analyze
4. **Processing Phase**: The system performs multiple security checks:
   - Domain reputation analysis
   - SSL certificate verification
   - Content analysis for phishing patterns
   - Malicious script detection
   - Redirect chain analysis
5. **Results Display**: Comprehensive security report with:
   - Overall safety score
   - Specific threats detected
   - Technical details about the website
   - Recommendations for user action

## 🚀 Future Enhancements

- **Browser Extension**: One-click URL analysis from any webpage
- **API Access**: Allow developers to integrate the scanning capabilities
- **Enhanced AI Detection**: Machine learning models to improve phishing detection
- **Batch URL Processing**: Scan multiple URLs simultaneously
- **PDF Report Generation**: Downloadable detailed security reports
- **Team Collaboration**: Share scan results with team members

## 📱 Interface Highlights

- **Login/Register**: Secure authentication screens with hacker-themed visuals
- **Dashboard**: Primary interface for URL scanning with real-time feedback
- **Results View**: Detailed breakdown of scan results with visual indicators
- **Matrix-inspired Background**: Dynamic code-rain animation effects
- **Terminal-style Components**: Command-line aesthetic throughout the application

## 🔐 Security Considerations

- All URL scanning is performed securely with proper input sanitization
- No sensitive user data is stored beyond what's necessary for authentication
- Strong password requirements enforce good security practices
- Educational components teach users about identifying phishing attempts

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
   - Set up authentication
   - Create necessary database tables
   - Configure environment variables

4. Start the development server:
   ```bash
   npm run dev
   # or
   yarn dev
   ```

5. Open your browser and navigate to `http://localhost:5173`

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- User interface components by [shadcn/ui](https://ui.shadcn.com/)
- Icons by [Lucide](https://lucide.dev/)
- Authentication provided by [Supabase](https://supabase.io/)
- Developed with React and TypeScript

---

© 2025 CyberSentry | Secure Network Analysis Tool
