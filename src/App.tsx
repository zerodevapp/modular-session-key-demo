import { useState } from 'react';
import { startAuthentication, startRegistration, browserSupportsWebAuthn, platformAuthenticatorIsAvailable, browserSupportsWebAuthnAutofill } from '@simplewebauthn/browser';
import './App.css';

function App() {
  const [status, setStatus] = useState<string>('');
  const [name, setName] = useState<string>('');
  const [message, setMessage] = useState<string>('');
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);

  const handleRegister = async () => {
    const optionsResponse = await fetch('http://localhost:8080/register/options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: name }), // Replace with actual username input if needed,
      credentials: 'include',
    });
    const options = await optionsResponse.json();
    setStatus(`Registration Options: ${JSON.stringify(options)}`);

    const cred = await startRegistration(options);

    const verifyResponse = await fetch('http://localhost:8080/register/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: name, cred }),
      credentials: 'include',
    });
    const verifyResult = await verifyResponse.json();
    setStatus(`Registration Verification: ${JSON.stringify(verifyResult)}`);


  };

  const handleAuthenticate = async () => {
    const optionsResponse = await fetch('http://localhost:8080/login/options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: name }),
      credentials: 'include',
    });
    const options = await optionsResponse.json();
    setStatus(`Authentication: ${JSON.stringify(options)}`);

    console.log(options);

    const cred = await startAuthentication(options);

    const verifyResponse = await fetch('http://localhost:8080/login/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cred }),
      credentials: 'include',
    });

    const verifyResult = await verifyResponse.json();
    setStatus(`Authentication Verification: ${JSON.stringify(verifyResult)}`);

    if (verifyResult.verified === true) {
      setIsAuthenticated(true);
      setMessage(verifyResult.message);
    }
  };

  const handleSignData = async () => {
    const signInitiateResponse = await fetch('http://localhost:8080/sign-initiate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: message }),
      credentials: 'include',
    });
    const signInitiateResult = await signInitiateResponse.json();
    setStatus(`Data Signature: ${JSON.stringify(signInitiateResult)}`);

    const assertionOptions = {
      challenge: signInitiateResult.challenge,
      allowCredentials: signInitiateResult.allowCredentials,
    };

    const cred = await startAuthentication(assertionOptions);

    const verifyResponse = await fetch('http://localhost:8080/sign-verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cred }),
      credentials: 'include',
    });

    const verifyResult = await verifyResponse.json();
    console.log("verifyResult", verifyResult)
    if (verifyResult.success) {
      console.log('Signature verified successfully');
      console.log('Signature:', verifyResult.signature); // Log the signature
    } else {
      console.log('Signature verification failed');
    }


  };



  return (
    <>
      <h1>WebAuthn Demo</h1>
      <div className="card">
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Enter your name"
        />
        <div>
          <button onClick={handleRegister}>Register</button>
          <button onClick={handleAuthenticate}>Authenticate</button>
        </div>
        <p>Status: {status}</p>
        {isAuthenticated && (
  <div className="card">
    <p>Authenticated!</p>
    <div className="input-group">
      <input
        key="message-input"
        type="text"
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        placeholder="Enter your message"
        className="input"
      /><div>
      <button onClick={handleSignData} className="button">Sign Data</button>
      </div>
    </div>
  </div>
)}
      </div>
    </>
  );
}

export default App;