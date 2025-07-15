// React Hook for Email Verification
// Copy this to your hooks folder

import { useState, useEffect, useCallback } from 'react';

interface EmailVerificationConfig {
  sendCodeEndpoint?: string;
  verifyCodeEndpoint?: string;
  autoSendOnMount?: boolean;
  resendDelay?: number; // seconds
}

interface VerificationResult {
  success: boolean;
  data?: any;
  error?: string;
}

interface VerificationState {
  codeId: string | null;
  isLoading: boolean;
  error: string | null;
  timeLeft: number;
  canResend: boolean;
  attempts: number;
  isCodeSent: boolean;
}

export function useEmailVerification(
  email: string,
  type: 'email_verification' | 'password_reset' = 'email_verification',
  config: EmailVerificationConfig = {}
) {
  const {
    sendCodeEndpoint = '/api/auth/send-verification-code',
    verifyCodeEndpoint = '/api/auth/verify-code',
    autoSendOnMount = false,
    resendDelay = 600 // 10 minutes
  } = config;

  const [state, setState] = useState<VerificationState>({
    codeId: null,
    isLoading: false,
    error: null,
    timeLeft: 0,
    canResend: false,
    attempts: 0,
    isCodeSent: false
  });

  // Timer for resend functionality
  useEffect(() => {
    if (state.timeLeft > 0) {
      const timer = setTimeout(() => {
        setState(prev => ({ ...prev, timeLeft: prev.timeLeft - 1 }));
      }, 1000);
      return () => clearTimeout(timer);
    } else if (state.codeId && state.isCodeSent) {
      setState(prev => ({ ...prev, canResend: true }));
    }
  }, [state.timeLeft, state.codeId, state.isCodeSent]);

  // Auto-send code on mount
  useEffect(() => {
    if (autoSendOnMount && email) {
      sendCode();
    }
  }, [email, autoSendOnMount]);

  const sendCode = useCallback(async (): Promise<VerificationResult> => {
    if (!email) {
      const error = 'Email is required';
      setState(prev => ({ ...prev, error }));
      return { success: false, error };
    }

    setState(prev => ({ 
      ...prev, 
      isLoading: true, 
      error: null, 
      canResend: false 
    }));

    try {
      const response = await fetch(sendCodeEndpoint, {
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
        timeLeft: resendDelay,
        error: null,
        attempts: 0,
        isCodeSent: true,
        isLoading: false
      }));

      // Show development code if available
      if (data.code && process.env.NODE_ENV === 'development') {
        console.log('Development verification code:', data.code);
      }

      return { success: true, data };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to send code';
      setState(prev => ({
        ...prev,
        error: errorMessage,
        canResend: true,
        isLoading: false
      }));

      return { success: false, error: errorMessage };
    }
  }, [email, type, sendCodeEndpoint, resendDelay]);

  const verifyCode = useCallback(async (code: string): Promise<VerificationResult> => {
    if (!state.codeId) {
      const error = 'No verification code sent. Please request a new code.';
      setState(prev => ({ ...prev, error }));
      return { success: false, error };
    }

    if (!code || code.length !== 6) {
      const error = 'Please enter a valid 6-digit code';
      setState(prev => ({ ...prev, error }));
      return { success: false, error };
    }

    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const response = await fetch(verifyCodeEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          codeId: state.codeId, 
          code: code.trim()
        }),
        credentials: 'include'
      });

      const data = await response.json();

      if (!response.ok) {
        setState(prev => ({ 
          ...prev, 
          error: data.error || 'Failed to verify code',
          attempts: prev.attempts + 1,
          isLoading: false
        }));
        return { success: false, error: data.error || 'Failed to verify code' };
      }

      // Success!
      setState(prev => ({
        ...prev,
        error: null,
        isLoading: false
      }));

      return { success: true, data };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to verify code';
      setState(prev => ({
        ...prev,
        error: errorMessage,
        attempts: prev.attempts + 1,
        isLoading: false
      }));

      return { success: false, error: errorMessage };
    }
  }, [state.codeId, verifyCodeEndpoint]);

  const resetState = useCallback(() => {
    setState({
      codeId: null,
      isLoading: false,
      error: null,
      timeLeft: 0,
      canResend: false,
      attempts: 0,
      isCodeSent: false
    });
  }, []);

  const formatTimeLeft = useCallback((seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  }, []);

  return {
    // State
    ...state,
    formattedTimeLeft: formatTimeLeft(state.timeLeft),
    
    // Actions
    sendCode,
    verifyCode,
    resetState,
    
    // Computed properties
    canSendCode: !state.isLoading && (!state.codeId || state.canResend),
    isMaxAttemptsReached: state.attempts >= 3,
    shouldShowResendButton: state.isCodeSent && (state.canResend || state.timeLeft === 0)
  };
}

// Usage Examples:

/* 
// 1. Basic Usage
import { useEmailVerification } from './useEmailVerification';

function VerifyEmailForm() {
  const [code, setCode] = useState('');
  const [email] = useState('user@example.com');
  
  const {
    isLoading,
    error,
    canSendCode,
    formattedTimeLeft,
    shouldShowResendButton,
    sendCode,
    verifyCode,
    isCodeSent
  } = useEmailVerification(email, 'email_verification', {
    autoSendOnMount: true
  });

  const handleVerify = async (e) => {
    e.preventDefault();
    const result = await verifyCode(code);
    if (result.success) {
      console.log('Verification successful:', result.data);
      // Handle success
    }
  };

  return (
    <form onSubmit={handleVerify}>
      <input 
        type="text"
        value={code}
        onChange={(e) => setCode(e.target.value)}
        placeholder="Enter 6-digit code"
        maxLength={6}
      />
      
      {error && <div className="error">{error}</div>}
      
      <button type="submit" disabled={isLoading || code.length !== 6}>
        {isLoading ? 'Verifying...' : 'Verify Code'}
      </button>
      
      {shouldShowResendButton && (
        <button 
          type="button" 
          onClick={sendCode}
          disabled={!canSendCode}
        >
          {canSendCode ? 'Resend Code' : `Resend in ${formattedTimeLeft}`}
        </button>
      )}
    </form>
  );
}

// 2. Password Reset Usage
function PasswordResetForm() {
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [step, setStep] = useState('email'); // 'email' | 'verify' | 'password'
  
  const verification = useEmailVerification(email, 'password_reset');

  const handleSendCode = async (e) => {
    e.preventDefault();
    const result = await verification.sendCode();
    if (result.success) {
      setStep('verify');
    }
  };

  const handleVerifyCode = async (e) => {
    e.preventDefault();
    const result = await verification.verifyCode(code);
    if (result.success) {
      setStep('password');
    }
  };

  if (step === 'email') {
    return (
      <form onSubmit={handleSendCode}>
        <input 
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="Enter your email"
          required
        />
        <button type="submit" disabled={verification.isLoading}>
          Send Reset Code
        </button>
      </form>
    );
  }

  if (step === 'verify') {
    return (
      <form onSubmit={handleVerifyCode}>
        <input 
          type="text"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder="Enter verification code"
          maxLength={6}
        />
        {verification.error && <div>{verification.error}</div>}
        <button type="submit" disabled={verification.isLoading}>
          Verify Code
        </button>
      </form>
    );
  }

  return (
    <form>
      <input 
        type="password"
        value={newPassword}
        onChange={(e) => setNewPassword(e.target.value)}
        placeholder="Enter new password"
      />
      <button type="submit">Reset Password</button>
    </form>
  );
}

// 3. Custom Configuration
function CustomVerificationFlow() {
  const verification = useEmailVerification(
    'user@example.com',
    'email_verification',
    {
      sendCodeEndpoint: '/api/custom/send-code',
      verifyCodeEndpoint: '/api/custom/verify-code',
      autoSendOnMount: false,
      resendDelay: 300 // 5 minutes
    }
  );

  return (
    <div>
      {verification.isCodeSent ? (
        <div>Code sent! Check your email.</div>
      ) : (
        <button onClick={verification.sendCode}>
          Send Verification Code
        </button>
      )}
    </div>
  );
}
*/
