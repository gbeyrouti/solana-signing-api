// API finale avec TweetNaCl (simple et fiable) - api/sign.js
import nacl from 'tweetnacl';

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

    console.log('🔑 Signature avec TweetNaCl (Ed25519 natif)');

    // Base58 et utilitaires
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

    console.log('🔓 Clé privée reçue, longueur:', privateKeyBytes.length);

    // Pour TweetNaCl, on a besoin de la clé complète (64 bytes) ou juste secrète (32 bytes)
    let keyPair;
    
    if (privateKeyBytes.length === 64) {
      // Clé Solana complète (secret + public)
      const secretKey = privateKeyBytes.slice(0, 32);
      keyPair = nacl.sign.keyPair.fromSecretKey(privateKeyBytes);
      console.log('🔑 Keypair créée depuis clé 64 bytes');
    } else if (privateKeyBytes.length === 32) {
      // Juste la partie secrète
      keyPair = nacl.sign.keyPair.fromSeed(privateKeyBytes);
      console.log('🔑 Keypair créée depuis seed 32 bytes');
    } else {
      throw new Error(`Longueur de clé invalide: ${privateKeyBytes.length} (attendu: 32 ou 64)`);
    }

    console.log('✅ Keypair TweetNaCl créée');
    console.log('  Clé publique longueur:', keyPair.publicKey.length);
    console.log('  Clé secrète longueur:', keyPair.secretKey.length);

    // Décoder transaction Jupiter
    const transactionBytes = base64ToBytes(transaction);
    console.log('📦 Transaction reçue, longueur:', transactionBytes.length);

    // Analyser structure Solana
    const numSignatures = transactionBytes[0];
    const messageStart = 1 + (numSignatures * 64);
    const messageBytes = transactionBytes.slice(messageStart);
    
    console.log('📄 Message à signer:');
    console.log('  Signatures requises:', numSignatures);
    console.log('  Offset message:', messageStart);
    console.log('  Longueur message:', messageBytes.length);
    console.log('  Premiers bytes:', Array.from(messageBytes.slice(0, 10)));

    // SIGNATURE ED25519 AVEC TWEETNACL
    console.log('🔏 Signature avec TweetNaCl...');
    
    const signature = nacl.sign.detached(messageBytes, keyPair.secretKey);
    
    console.log('✅ SIGNATURE TWEETNACL RÉUSSIE !');
    console.log('🎯 Signature longueur:', signature.length);
    console.log('🔢 Type signature:', signature.constructor.name);
    console.log('🔍 Signature bytes:', Array.from(signature.slice(0, 8)), '...');

    // Vérifier la signature (optionnel, pour debug)
    const isValid = nacl.sign.detached.verify(messageBytes, signature, keyPair.publicKey);
    console.log('🧪 Vérification signature:', isValid ? '✅ VALIDE' : '❌ INVALIDE');

    if (!isValid) {
      throw new Error('La signature générée n\'est pas valide lors de la vérification');
    }

    // Construire transaction signée
    const signedTransactionBytes = new Uint8Array(transactionBytes);
    signedTransactionBytes.set(signature, 1);

    console.log('🔧 Signature insérée dans la transaction à l\'offset 1');

    // Encoder résultat final
    const signedTransactionB64 = bytesToBase64(signedTransactionBytes);
    const signatureB58 = base58Encode(signature);

    console.log('🎉 TRANSACTION FINALE PRÊTE AVEC TWEETNACL !');
    console.log('📏 Longueur finale:', signedTransactionB64.length, 'caractères');

    return res.status(200).json({
      success: true,
      signedTransaction: signedTransactionB64,
      signature: signatureB58,
      method: 'TweetNaCl-Ed25519-Native',
      timestamp: new Date().toISOString(),
      debug: {
        library: 'tweetnacl',
        verified: isValid,
        originalLength: transactionBytes.length,
        messageStart: messageStart,
        messageLength: messageBytes.length,
        signatureLength: signature.length,
        signatureType: signature.constructor.name,
        keyPairValid: !!(keyPair.publicKey && keyPair.secretKey),
        finalLength: signedTransactionB64.length
      }
    });

  } catch (error) {
    console.error('❌ Erreur TweetNaCl:', error);
    
    return res.status(500).json({
      success: false,
      error: error.message,
      timestamp: new Date().toISOString(),
      library: 'tweetnacl'
    });
  }
}
