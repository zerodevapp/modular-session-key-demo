import { useState } from 'react';
import { startAuthentication, startRegistration, browserSupportsWebAuthn, platformAuthenticatorIsAvailable, browserSupportsWebAuthnAutofill } from '@simplewebauthn/browser';
import { b64ToBytes, uint8ArrayToHexString, verify, splitECDSASignature, convertBase64PublicKeyToXY, findQuoteIndices, parseAndNormalizeSig } from '../utils';
import { toBytes } from 'viem';
import './App.css';

function App() {
  const [status, setStatus] = useState<string>('');
  const [name, setName] = useState<string>('');
  const [message, setMessage] = useState<string>('');
  const [signature, setSignature] = useState<string>('');
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [authenticatorData, setAuthenticatorData] = useState<string>('');

  const fetchDummySignature = async (userId: string) => {
    const response = await fetch(`http://localhost:8080/dummy-signature/${userId}`);
    const result = await response.json();
    return result.dummySignature;
  }

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
    setAuthenticatorData(JSON.stringify(verifyResult.authenticationInfo, null, 2));

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
    setAuthenticatorData(JSON.stringify(verifyResult.authenticationInfo, null, 2));
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

    console.log("message", message);
    console.log("signInitiateResult.challenge", signInitiateResult.challenge);
    const challengeBase64 = signInitiateResult.challenge;
    console.log("challengeBase64", challengeBase64);

    const challengeArrayBuffer = b64ToBytes(challengeBase64);
    console.log("challengeArrayBuffer", challengeArrayBuffer);
    const challengeUint8Array = new Uint8Array(challengeArrayBuffer);
    console.log("challengeUint8Array", challengeUint8Array);
    
    // Convert Uint8Array to hex string
    const challengeHex = uint8ArrayToHexString(challengeUint8Array);
    console.log("challengeHex", challengeHex);

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
    setAuthenticatorData(JSON.stringify(verifyResult.authenticationInfo, null, 2));
    if (verifyResult.success) {
      console.log('Signature verified successfully');
      const signature = verifyResult.signature;
      const authenticatorData = verifyResult.authenticatorData;

      const authenticatorDataHex = uint8ArrayToHexString(b64ToBytes(authenticatorData));
      const signatureHex = uint8ArrayToHexString(b64ToBytes(signature));

      const {r, s} = parseAndNormalizeSig(signatureHex);

      const publicKeyBase64 = verifyResult.publicKeyBase64;




      const { x, y } = convertBase64PublicKeyToXY(publicKeyBase64);

      const clientDataJSON = atob(cred.response.clientDataJSON);


      const { beforeT, beforeChallenge } = findQuoteIndices(clientDataJSON);



      // const publicKeyHex = uint8ArrayToHexString(b64ToBytes(publicKey));

      const verified = await verify(challengeHex, authenticatorDataHex, true, clientDataJSON, beforeChallenge, beforeT, BigInt(r), BigInt(s), BigInt(x), BigInt(y));

      console.log("verified", verified);
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
        {authenticatorData && (
          <div className="card">
            <h2>Authenticator Data</h2>
            <pre>{authenticatorData}</pre>
          </div>
        )}

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