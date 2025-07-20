// api/sign.js - API de signature Solana pour Vercel
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

    // Import des bibliothèques crypto (disponibles sur Vercel)
    const { webcrypto } = await import('crypto');
    const crypto = webcrypto;

    // Fonction de signature Ed25519 simple
    async function signEd25519(message, privateKeyBytes) {
      // Import de la clé privée
      const keyData = privateKeyBytes.slice(0, 32);
      
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyData,
        {
          name: 'Ed25519',
          namedCurve: 'Ed25519'
        },
        false,
        ['sign']
      );

      // Signer le message
      const signature = await crypto.subtle.sign('Ed25519', cryptoKey, message);
      return new Uint8Array(signature);
    }

    // Base58 encoding simple (sans dépendances)
    const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    
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
      
      // Convert leading zeros
      let leadingZeros = 0;
      for (let k = 0; k < buffer.length && buffer[k] === 0; k++) {
        leadingZeros++;
      }
      
      return ALPHABET[0].repeat(leadingZeros) + 
             digits.reverse().map(digit => ALPHABET[digit]).join('');
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
      
      // Handle leading zeros
      let leadingZeros = 0;
      for (let k = 0; k < string.length && string[k] === ALPHABET[0]; k++) {
        leadingZeros++;
      }
      
      const result = new Uint8Array(leadingZeros + bytes.length);
      result.set(bytes.reverse(), leadingZeros);
      return result;
    }

    // Traitement de la clé privée
    let privateKeyBytes;
    if (typeof privateKey === 'string') {
      try {
        // Essayer base58
        privateKeyBytes = base58Decode(privateKey);
      } catch {
        // Essayer JSON array
        const keyArray = JSON.parse(privateKey);
        privateKeyBytes = new Uint8Array(keyArray);
      }
    } else if (Array.isArray(privateKey)) {
      privateKeyBytes = new Uint8Array(privateKey);
    } else {
      throw new Error('Format de clé privée non supporté');
    }

    // Vérification de la longueur de la clé
    if (privateKeyBytes.length < 32) {
      throw new Error('Clé privée trop courte');
    }

    // Décoder la transaction
    const transactionBytes = Buffer.from(transaction, 'base64');
    
    // Signer la transaction
    const signature = await signEd25519(transactionBytes, privateKeyBytes);
    
    // Pour Solana, nous devons ajouter la signature à la transaction
    // Structure simplifiée : signature + transaction
    const signedTransactionBytes = new Uint8Array(signature.length + transactionBytes.length);
    signedTransactionBytes.set(signature, 0);
    signedTransactionBytes.set(transactionBytes, signature.length);
    
    const signedTransaction = Buffer.from(signedTransactionBytes).toString('base64');
    const signatureB58 = base58Encode(signature);

    console.log('✅ Transaction signée avec succès');
    console.log('🔑 Signature length:', signature.length);
    console.log('📦 Transaction length:', transactionBytes.length);

    return res.status(200).json({
      success: true,
      signedTransaction: signedTransaction,
      signature: signatureB58,
      method: 'Ed25519-WebCrypto',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('❌ Erreur de signature:', error);
    
    return res.status(500).json({
      success: false,
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
}
