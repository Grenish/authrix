// React Email Verification Component
// Copy this to your React components folder

import React, { useState, useEffect } from 'react';

interface EmailVerificationProps {
  email: string;
  onSuccess: (result: any) => void;
  onCancel?: () => void;
  type?: 'email_verification' | 'password_reset';
  apiEndpoints?: {
    sendCode?: string;
    verifyCode?: string;
  };
}

interface VerificationState {
  codeId: string | null;
  code: string;
  loading: boolean;
  error: string | null;
  timeLeft: number;
  canResend: boolean;
  attempts: number;
}

export function EmailVerification({
  email,
  onSuccess,
  onCancel,
  type = 'email_verification',
  apiEndpoints = {
    sendCode: '/api/auth/send-verification-code',
    verifyCode: '/api/auth/verify-code'
  }
}: EmailVerificationProps) {
  const [state, setState] = useState<VerificationState>({
    codeId: null,
    code: '',
    loading: false,
    error: null,
    timeLeft: 0,
    canResend: false,
    attempts: 0
  });

  // Timer for resend functionality
  useEffect(() => {
    if (state.timeLeft > 0) {
      const timer = setTimeout(() => {
        setState(prev => ({ ...prev, timeLeft: prev.timeLeft - 1 }));
      }, 1000);
      return () => clearTimeout(timer);
    } else if (state.codeId) {
      setState(prev => ({ ...prev, canResend: true }));
    }
  }, [state.timeLeft, state.codeId]);

  // Send initial code on mount
  useEffect(() => {
    sendCode();
  }, []);

  const sendCode = async () => {
    setState(prev => ({ ...prev, loading: true, error: null, canResend: false }));

    try {
      const response = await fetch(apiEndpoints.sendCode!, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, type }),
        credentials: 'include'
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to send verification code');
      }

      setState(prev => ({
        ...prev,
        codeId: data.codeId,
        timeLeft: 600, // 10 minutes
        error: null,
        attempts: 0
      }));

      // Show development code if available
      if (data.code && process.env.NODE_ENV === 'development') {
        console.log('Development verification code:', data.code);
      }

    } catch (error) {
      setState(prev => ({
        ...prev,
        error: error instanceof Error ? error.message : 'Failed to send code',
        canResend: true
      }));
    } finally {
      setState(prev => ({ ...prev, loading: false }));
    }
  };

  const verifyCode = async () => {
    if (!state.codeId || !state.code || state.code.length !== 6) return;

    setState(prev => ({ ...prev, loading: true, error: null }));

    try {
      const response = await fetch(apiEndpoints.verifyCode!, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          codeId: state.codeId, 
          code: state.code 
        }),
        credentials: 'include'
      });

      const data = await response.json();

      if (!response.ok) {
        setState(prev => ({ 
          ...prev, 
          error: data.error || 'Failed to verify code',
          attempts: prev.attempts + 1
        }));
        return;
      }

      // Success!
      onSuccess(data);

    } catch (error) {
      setState(prev => ({
        ...prev,
        error: error instanceof Error ? error.message : 'Failed to verify code',
        attempts: prev.attempts + 1
      }));
    } finally {
      setState(prev => ({ ...prev, loading: false }));
    }
  };

  const handleCodeChange = (value: string) => {
    // Only allow digits and limit to 6 characters
    const sanitized = value.replace(/\D/g, '').slice(0, 6);
    setState(prev => ({ ...prev, code: sanitized, error: null }));
  };

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const getTitle = () => {
    switch (type) {
      case 'password_reset':
        return 'Reset Your Password';
      case 'email_verification':
      default:
        return 'Verify Your Email';
    }
  };

  const getDescription = () => {
    switch (type) {
      case 'password_reset':
        return `We've sent a password reset code to ${email}`;
      case 'email_verification':
      default:
        return `We've sent a verification code to ${email}`;
    }
  };

  return (
    <div className="max-w-md mx-auto p-6 bg-white rounded-lg shadow-lg border border-gray-200">
      <div className="text-center mb-6">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">
          {getTitle()}
        </h2>
        <p className="text-gray-600">
          {getDescription()}
        </p>
      </div>

      <div className="space-y-4">
        {/* Code Input */}
        <div>
          <label htmlFor="verification-code" className="block text-sm font-medium text-gray-700 mb-2">
            Verification Code
          </label>
          <input
            id="verification-code"
            type="text"
            value={state.code}
            onChange={(e) => handleCodeChange(e.target.value)}
            placeholder="Enter 6-digit code"
            className="w-full px-4 py-3 text-center text-lg font-mono border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            maxLength={6}
            disabled={state.loading}
            autoComplete="one-time-code"
          />
        </div>

        {/* Error Display */}
        {state.error && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
            <p className="text-red-700 text-sm">{state.error}</p>
            {state.attempts >= 2 && (
              <p className="text-red-600 text-xs mt-1">
                Too many failed attempts. Please request a new code.
              </p>
            )}
          </div>
        )}

        {/* Success Messages */}
        {state.codeId && !state.error && (
          <div className="p-3 bg-green-50 border border-green-200 rounded-lg">
            <p className="text-green-700 text-sm">
              Verification code sent successfully!
            </p>
          </div>
        )}

        {/* Verify Button */}
        <button
          onClick={verifyCode}
          disabled={state.loading || state.code.length !== 6 || !state.codeId}
          className="w-full bg-blue-600 text-white py-3 px-4 rounded-lg font-medium hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {state.loading ? (
            <span className="flex items-center justify-center">
              <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              Verifying...
            </span>
          ) : (
            'Verify Code'
          )}
        </button>

        {/* Resend Section */}
        <div className="text-center">
          {state.timeLeft > 0 ? (
            <p className="text-gray-600 text-sm">
              Resend code in {formatTime(state.timeLeft)}
            </p>
          ) : (
            <button
              onClick={sendCode}
              disabled={state.loading || !state.canResend}
              className="text-blue-600 hover:text-blue-800 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {state.loading ? 'Sending...' : 'Resend Code'}
            </button>
          )}
        </div>

        {/* Cancel Button */}
        {onCancel && (
          <button
            onClick={onCancel}
            disabled={state.loading}
            className="w-full bg-gray-100 text-gray-700 py-2 px-4 rounded-lg font-medium hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 disabled:opacity-50 transition-colors"
          >
            Cancel
          </button>
        )}

        {/* Development Helper */}
        {process.env.NODE_ENV === 'development' && (
          <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
            <p className="text-yellow-700 text-xs">
              <strong>Development Mode:</strong> Check console for verification code
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

// Usage Example:
/*
import { EmailVerification } from './EmailVerification';

function MyComponent() {
  const [showVerification, setShowVerification] = useState(false);
  const [email, setEmail] = useState('');

  const handleVerificationSuccess = (result) => {
    console.log('Verification successful:', result);
    setShowVerification(false);
    // Handle success (e.g., redirect, update UI, etc.)
  };

  if (showVerification) {
    return (
      <EmailVerification
        email={email}
        onSuccess={handleVerificationSuccess}
        onCancel={() => setShowVerification(false)}
        type="email_verification"
      />
    );
  }

  return (
    <div>
      <input 
        type="email" 
        value={email} 
        onChange={(e) => setEmail(e.target.value)} 
        placeholder="Enter your email"
      />
      <button onClick={() => setShowVerification(true)}>
        Send Verification Code
      </button>
    </div>
  );
}
*/
