
# PhishGuard - Phishing Link Detector

![PhishGuard](https://img.shields.io/badge/PhishGuard-Cyber%20Security-blue)

PhishGuard is a sophisticated web-based cybersecurity tool designed to detect and analyze potential phishing links. The application provides real-time scanning of URLs to identify threats and security vulnerabilities, helping users stay protected against online scams and phishing attempts.

## 🔒 Features

- **URL Threat Detection**: Analyze URLs for phishing attempts and security risks
- **Security Scoring**: Get a safety score out of 100 for any analyzed URL
- **Threat Identification**: Detailed breakdown of detected security issues
- **Domain Analysis**: Information about domain age, SSL status, and redirects
- **User Authentication**: Secure login and registration system
- **Responsive Interface**: Professional dark-themed UI optimized for all devices

## 🛠️ Technology Stack

- **Frontend**: React, TypeScript, TailwindCSS, shadcn/ui
- **State Management**: React Context API, React Query
- **Authentication**: Supabase Auth (implementation ready)
- **Styling**: Custom cybersecurity-themed UI with animations
- **Notifications**: Toast notifications for user feedback

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

PhishGuard is designed to work with Supabase for authentication and data storage. To connect your Supabase database:

1. Create a Supabase project at [https://supabase.com](https://supabase.com)
2. Set up authentication in your Supabase project
3. Connect your Supabase project to PhishGuard:
   - Click on the Supabase button in the Lovable interface
   - Connect to your Supabase project
   - Follow the integration steps

### Database Schema

Create the following tables in your Supabase project:

**Users Table** (handled automatically by Supabase Auth)
- id: uuid (primary key)
- email: text
- created_at: timestamp

**Scan History Table**
- id: uuid (primary key)
- user_id: uuid (foreign key to users.id)
- url: text
- score: integer
- threats: json
- scanned_at: timestamp

## 📱 Interface

PhishGuard features a professional dark-themed interface designed specifically for cybersecurity applications:

- **Login/Register**: Secure authentication screens
- **Dashboard**: URL scanning interface with real-time analysis
- **Results View**: Detailed breakdown of scan results with visual indicators
- **Mobile Responsive**: Fully functional on all device sizes

## 🔐 Security Notes

- All URL scanning is performed securely
- No sensitive user data is stored
- Password requirements enforce strong security practices
- The application includes anti-phishing education elements

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- Icons by [Lucide](https://lucide.dev/)
- UI Components by [shadcn/ui](https://ui.shadcn.com/)
- Developed with [Lovable](https://lovable.dev/)

---

© 2025 PhishGuard | Secure Link Analysis Tool
