
# PhishGuard - AI-Powered Phishing Link Detector

![PhishGuard](https://img.shields.io/badge/PhishGuard-Cyber%20Security-blue)

PhishGuard is a sophisticated web-based cybersecurity tool designed to detect and analyze potential phishing links. The application provides real-time scanning of URLs to identify threats and security vulnerabilities, helping users stay protected against online scams and phishing attempts.

## 🔒 Features

- **AI-Powered URL Analysis**: Advanced machine learning algorithms detect phishing attempts
- **Consistent Security Scoring**: Reliable and repeatable security assessments
- **Multi-Vector Security Analysis**: Comprehensive checking across multiple security dimensions
- **Mobile-Responsive Design**: Fully functional on all device sizes
- **User Authentication**: Secure login and registration system
- **Cybersecurity Interface**: Professional dark-themed UI with cyber aesthetics

## 🛠️ Technology Stack

- **Frontend**: React, TypeScript, TailwindCSS, shadcn/ui
- **Backend**: Supabase Edge Functions
- **Authentication**: Supabase Auth
- **State Management**: React Context API, React Query
- **Styling**: Custom cybersecurity-themed UI with animations
- **Notifications**: Toast notifications for user feedback

## 🔍 URL Analysis Methodology

PhishGuard scans URLs using multiple security vectors:

1. **Domain Reputation** - Checks against known safe and malicious domains
2. **URL Structure Analysis** - Detects suspicious patterns in URL formation
3. **SSL Certificate Verification** - Ensures proper encryption protocols
4. **WHOIS Information** - Examines domain registration details and age
5. **Redirect Behavior Analysis** - Checks for suspicious redirects or forced downloads
6. **IP Reputation** - Evaluates the reputation of the hosting server
7. **ML Classification** - AI model prediction based on URL characteristics

## 🚀 Getting Started

### Prerequisites

- Node.js (v14.0 or higher)
- npm or yarn

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/phishguard.git
   cd phishguard
   ```

2. Install dependencies:
   ```bash
   npm install
   # or
   yarn install
   ```

3. Start the development server:
   ```bash
   npm run dev
   # or
   yarn dev
   ```

4. Open your browser and navigate to `http://localhost:8080`

## 🔧 Supabase Integration

PhishGuard uses Supabase for authentication and edge functions:

1. Create a Supabase project at [https://supabase.com](https://supabase.com)
2. Connect your Supabase project to PhishGuard:
   - Click on the Supabase button in the Lovable interface
   - Connect to your Supabase project
   - Follow the integration steps

### Database Schema

**Users Table** (handled automatically by Supabase Auth)
- id: uuid (primary key)
- email: text
- created_at: timestamp

**Profiles Table**
- id: uuid (primary key, references users.id)
- username: text

**Scan History Table**
- id: uuid (primary key)
- user_id: uuid (foreign key to users.id)
- url: text
- score: integer
- threats: json
- is_safe: boolean
- scanned_at: timestamp

## 📱 Key UI Features

- **Responsive Design**: Fully functional across all device sizes
- **Username Highlighting**: Prominent display of user identity
- **Real-time Scan Visualization**: Dynamic feedback during scan process
- **Detailed Security Reports**: Comprehensive breakdown of security factors
- **Cybersecurity Aesthetics**: Terminal-inspired security interface

## 🔐 Security Notes

- All URL scanning is performed securely via edge functions
- Consistent security scoring for reliable results
- Enhanced AI model for accurate threat detection
- Mobile-friendly security interface

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- Icons by [Lucide](https://lucide.dev/)
- UI Components by [shadcn/ui](https://ui.shadcn.com/)
- Developed with [Lovable](https://lovable.dev/)

---

© 2025 PhishGuard | Secure Link Analysis Tool
