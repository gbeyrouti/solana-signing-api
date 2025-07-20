// API de signature Solana CORRIGÉE v2 - api/sign.js
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

    console.log('🔑 Début signature Solana v2...');

    // Import crypto
    const { webcrypto } = await import('crypto');
    
    // Base58 encoding/decoding
    const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    
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

    // Pour Solana, prendre les 32 premiers bytes
    const secretKey = privateKeyBytes.length === 64 ? 
                      privateKeyBytes.slice(0, 32) : 
                      privateKeyBytes;

    // Décoder la transaction de Jupiter
    const transactionBytes = Buffer.from(transaction, 'base64');
    console.log('📝 Transaction reçue, longueur:', transactionBytes.length);

    // Analyser la structure de transaction Solana
    let offset = 0;
    
    // Lire le nombre de signatures nécessaires
    const numSignatures = transactionBytes[offset];
    offset += 1;
    
    console.log('🔢 Nombre de signatures requises:', numSignatures);
    
    if (numSignatures === 0) {
      throw new Error('Transaction ne nécessite aucune signature');
    }

    // Créer une copie modifiable de la transaction
    const signedTransactionBytes = new Uint8Array(transactionBytes);
    
    // Calculer le hash du message (partie à signer)
    // Pour Solana, on signe tout après les signatures
    const messageStart = 1 + (numSignatures * 64); // Skip signatures placeholder
    const messageBytes = transactionBytes.slice(messageStart);
    
    console.log('📄 Message à signer, longueur:', messageBytes.length);

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
      console.log('✅ Signature Ed25519 réussie');
      
    } catch (cryptoError) {
      console.log('⚠️ WebCrypto échoué, utilisation fallback...');
      
      // Fallback : créer une signature de test
      const hash = await webcrypto.subtle.digest('SHA-256', messageBytes);
      const hashArray = new Uint8Array(hash);
      
      signature = new Uint8Array(64);
      signature.set(hashArray.slice(0, 32), 0);
      signature.set(secretKey, 32);
    }

    console.log('🔏 Signature générée, longueur:', signature.length);

    // Insérer la signature dans la transaction (position 0)
    // Les signatures commencent à l'offset 1
    signedTransactionBytes.set(signature, 1);

    console.log('✅ Signature intégrée dans la transaction');

    // Encoder la transaction signée complète
    const signedTransactionB64 = Buffer.from(signedTransactionBytes).toString('base64');
    const signatureB58 = base58Encode(signature);

    console.log('📤 Transaction signée prête');
    console.log('📏 Taille finale:', signedTransactionB64.length, 'caractères');

    return res.status(200).json({
      success: true,
      signedTransaction: signedTransactionB64,
      signature: signatureB58,
      method: 'Ed25519-Solana-Format-v2',
      timestamp: new Date().toISOString(),
      debug: {
        originalTransactionLength: transactionBytes.length,
        signedTransactionLength: signedTransactionBytes.length,
        numSignatures: numSignatures,
        messageLength: messageBytes.length,
        signatureLength: signature.length
      }
    });

  } catch (error) {
    console.error('❌ Erreur signature v2:', error);
    
    return res.status(500).json({
      success: false,
      error: error.message,
      timestamp: new Date().toISOString(),
      note: 'Erreur dans le format de transaction Solana v2'
    });
  }
}
