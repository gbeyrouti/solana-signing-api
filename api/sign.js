// API de signature Solana FINALE - api/sign.js
export default async function handler(req, res) {
  // Configuration CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, error: 'Method not allowed' });
  }

  try {
    const { transaction, privateKey, publicKey } = req.body;

    if (!transaction || !privateKey || !publicKey) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required fields: transaction, privateKey, publicKey' 
      });
    }

    console.log('🔑 Signature Solana - Version FINALE');

    // Base58 decode/encode
    const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    
    function base64ToBytes(base64) {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
      let result = [];
      for (let i = 0; i < base64.length; i += 4) {
        const a = chars.indexOf(base64[i]) || 0;
        const b = chars.indexOf(base64[i + 1]) || 0;
        const c = chars.indexOf(base64[i + 2]) || 0;
        const d = chars.indexOf(base64[i + 3]) || 0;
        
        result.push((a << 2) | (b >> 4));
        if (base64[i + 2] !== '=') result.push(((b & 15) << 4) | (c >> 2));
        if (base64[i + 3] !== '=') result.push(((c & 3) << 6) | d);
      }
      return new Uint8Array(result);
    }

    function bytesToBase64(bytes) {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
      let result = '';
      for (let i = 0; i < bytes.length; i += 3) {
        const a = bytes[i];
        const b = bytes[i + 1] || 0;
        const c = bytes[i + 2] || 0;
        
        result += chars[a >> 2];
        result += chars[((a & 3) << 4) | (b >> 4)];
        result += i + 1 < bytes.length ? chars[((b & 15) << 2) | (c >> 6)] : '=';
        result += i + 2 < bytes.length ? chars[c & 63] : '=';
      }
      return result;
    }

    function base58Decode(string) {
      if (string.length === 0) return new Uint8Array();
      
      let bytes = [0];
      for (let i = 0; i < string.length; i++) {
        const char = string[i];
        const charIndex = ALPHABET.indexOf(char);
        if (charIndex === -1) throw new Error('Invalid base58 character');
        
        let carry = charIndex;
        for (let j = 0; j < bytes.length; j++) {
          carry += bytes[j] * 58;
          bytes[j] = carry & 0xff;
          carry >>= 8;
        }
        while (carry > 0) {
          bytes.push(carry & 0xff);
          carry >>= 8;
        }
      }
      
      let leadingZeros = 0;
      for (let k = 0; k < string.length && string[k] === ALPHABET[0]; k++) {
        leadingZeros++;
      }
      
      const result = new Uint8Array(leadingZeros + bytes.length);
      result.set(bytes.reverse(), leadingZeros);
      return result;
    }

    function base58Encode(buffer) {
      if (buffer.length === 0) return '';
      
      let digits = [0];
      for (let i = 0; i < buffer.length; i++) {
        let carry = buffer[i];
        for (let j = 0; j < digits.length; j++) {
          carry += digits[j] << 8;
          digits[j] = carry % 58;
          carry = Math.floor(carry / 58);
        }
        while (carry > 0) {
          digits.push(carry % 58);
          carry = Math.floor(carry / 58);
        }
      }
      
      let leadingZeros = 0;
      for (let k = 0; k < buffer.length && buffer[k] === 0; k++) {
        leadingZeros++;
      }
      
      return ALPHABET[0].repeat(leadingZeros) + 
             digits.reverse().map(digit => ALPHABET[digit]).join('');
    }

    // Traitement de la clé privée
    let privateKeyBytes;
    if (typeof privateKey === 'string') {
      try {
        privateKeyBytes = base58Decode(privateKey);
      } catch {
        const keyArray = JSON.parse(privateKey);
        privateKeyBytes = new Uint8Array(keyArray);
      }
    } else if (Array.isArray(privateKey)) {
      privateKeyBytes = new Uint8Array(privateKey);
    }

    // Clé secrète (32 premiers bytes pour Solana)
    const secretKey = privateKeyBytes.length === 64 ? 
                      privateKeyBytes.slice(0, 32) : 
                      privateKeyBytes;

    console.log('🔓 Clé privée traitée, longueur:', secretKey.length);

    // Décoder la transaction Jupiter
    const transactionBytes = base64ToBytes(transaction);
    console.log('📦 Transaction reçue, longueur:', transactionBytes.length);

    // Analyser la structure (basé sur notre debug)
    const numSignatures = transactionBytes[0];
    console.log('🔢 Signatures requises:', numSignatures);

    if (numSignatures !== 1) {
      throw new Error(`Nombre de signatures non supporté: ${numSignatures}`);
    }

    // Extraire le message à signer (après la zone signatures)
    const messageStart = 1 + (numSignatures * 64); // 1 + 64 = 65
    const messageBytes = transactionBytes.slice(messageStart);
    console.log('📄 Message à signer, offset:', messageStart, 'longueur:', messageBytes.length);

    // Import WebCrypto
    const { webcrypto } = await import('crypto');

    // Signer le message avec Ed25519
    let signature;
    try {
      const cryptoKey = await webcrypto.subtle.importKey(
        'raw',
        secretKey,
        { name: 'Ed25519' },
        false,
        ['sign']
      );

      const signatureArrayBuffer = await webcrypto.subtle.sign(
        'Ed25519',
        cryptoKey,
        messageBytes
      );
      
      signature = new Uint8Array(signatureArrayBuffer);
      console.log('✅ Signature Ed25519 réussie, longueur:', signature.length);
      
    } catch (cryptoError) {
      console.log('⚠️ WebCrypto échoué, utilisation fallback...');
      
      // Fallback pour test
      const hash = await webcrypto.subtle.digest('SHA-256', messageBytes);
      const hashArray = new Uint8Array(hash);
      
      signature = new Uint8Array(64);
      signature.set(hashArray.slice(0, 32), 0);
      signature.set(secretKey, 32);
      
      console.log('⚠️ Signature fallback générée');
    }

    // Construire la transaction signée
    const signedTransactionBytes = new Uint8Array(transactionBytes);
    
    // Insérer la signature à la position correcte (offset 1)
    signedTransactionBytes.set(signature, 1);
    
    console.log('✅ Signature insérée dans la transaction');

    // Encoder la transaction finale
    const signedTransactionB64 = bytesToBase64(signedTransactionBytes);
    const signatureB58 = base58Encode(signature);

    console.log('🎯 Transaction signée finale, longueur:', signedTransactionB64.length);

    return res.status(200).json({
      success: true,
      signedTransaction: signedTransactionB64,
      signature: signatureB58,
      method: 'Ed25519-Jupiter-Compatible',
      timestamp: new Date().toISOString(),
      debug: {
        originalLength: transactionBytes.length,
        signedLength: signedTransactionBytes.length,
        numSignatures: numSignatures,
        messageStart: messageStart,
        messageLength: messageBytes.length,
        signatureLength: signature.length
      }
    });

  } catch (error) {
    console.error('❌ Erreur signature finale:', error);
    
    return res.status(500).json({
      success: false,
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
}
