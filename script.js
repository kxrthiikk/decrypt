/**
 * Matches decrypt.php: AES-256-CBC, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
 * decrypt strips [\x00-\x1F\x7F] and trim. encrypt_payload null-pads UTF-8
 * plaintext to a 16-byte boundary before encrypt (via CryptoJS pad NoPadding).
 * Requires CryptoJS (see index.html script tag).
 */

const DEFAULT_CIPHER_KEY_HEX =
    '58120C891223112818424CF0CEF8CA3569D340F77CCD25D3CD90AC57686535E9';

const modeRadios = document.querySelectorAll('input[name="mode"]');
const decryptFields = document.getElementById('decrypt-fields');
const encryptFields = document.getElementById('encrypt-fields');
const submitBtn = document.getElementById('submit-btn');
const cipherKeyInput = document.getElementById('cipher-key');

const errorBox = document.getElementById('error');
const resultBox = document.getElementById('result');
const resultContent = document.getElementById('result-content');
const resultLabel = document.querySelector('.result-label');

if (cipherKeyInput && !cipherKeyInput.value.trim()) {
    cipherKeyInput.value = DEFAULT_CIPHER_KEY_HEX;
}

function syncMode() {
    const isEncrypt = document.querySelector('input[value="encrypt"]').checked;

    decryptFields.style.display = isEncrypt ? 'none' : 'block';
    encryptFields.style.display = isEncrypt ? 'block' : 'none';

    submitBtn.textContent = isEncrypt ? 'Encrypt' : 'Decrypt';
}

modeRadios.forEach((radio) => {
    radio.addEventListener('change', syncMode);
});

syncMode();

function hexToUint8Array(hex) {
    const cleaned = String(hex).replace(/\s/g, '');
    if (cleaned.length % 2 !== 0) {
        throw new Error('Hex string must have an even number of characters');
    }
    const pairs = cleaned.match(/[0-9a-fA-F]{2}/g);
    if (!pairs || pairs.length * 2 !== cleaned.length) {
        throw new Error('Hex string contains invalid characters');
    }
    return new Uint8Array(pairs.map((byte) => parseInt(byte, 16)));
}

function removeControlChars(str) {
    return str.replace(/[\x00-\x1F\x7F]/g, '').trim();
}

function getKeyHex() {
    const v = cipherKeyInput && cipherKeyInput.value.trim();
    return v || DEFAULT_CIPHER_KEY_HEX;
}

/** decrypt.php uses AES-256-CBC and hex2bin($keyHex) — 32-byte key. */
function parseKeyHexWordArray() {
    const cleaned = getKeyHex().replace(/\s/g, '');
    const bytes = hexToUint8Array(cleaned);
    if (bytes.length !== 32) {
        throw new Error(
            'decrypt.php uses AES-256-CBC: key hex must decode to exactly 32 bytes (64 hex characters).'
        );
    }
    return CryptoJS.enc.Hex.parse(cleaned);
}

function ivHexToWordArray(ivHex) {
    const cleaned = String(ivHex).replace(/\s/g, '');
    if (cleaned.length !== 32) {
        throw new Error(
            'id must be 32 hex characters (16-byte IV), same as decrypt.php / openssl_cipher_iv_length.'
        );
    }
    return CryptoJS.enc.Hex.parse(cleaned);
}

function base64ToWordArray(base64) {
    const cleaned = String(base64).replace(/\s/g, '');
    return CryptoJS.enc.Base64.parse(cleaned);
}

/** Same as PHP encrypt_payload: UTF-8 bytes, then zero-pad to 16-byte boundary. */
function utf8NullPadToBlock(plainText) {
    const enc = new TextEncoder();
    const bytes = enc.encode(plainText);
    const block = 16;
    const r = bytes.length % block;
    if (r === 0) {
        return bytes;
    }
    const out = new Uint8Array(bytes.length + (block - r));
    out.set(bytes);
    return out;
}

function uint8ToLatin1WordArray(u8) {
    const parts = [];
    const chunk = 8192;
    for (let i = 0; i < u8.length; i += chunk) {
        let s = '';
        const end = Math.min(i + chunk, u8.length);
        for (let j = i; j < end; j++) {
            s += String.fromCharCode(u8[j]);
        }
        parts.push(s);
    }
    return CryptoJS.enc.Latin1.parse(parts.join(''));
}

/**
 * decrypt.php decrypt(): openssl_decrypt(..., OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING),
 * then preg_replace('/[\x00-\x1F\x7F]/u', '', $raw) and trim().
 */
function phpStyleDecrypt(documentB64, ivHex) {
    const keyWA = parseKeyHexWordArray();
    const ivWA = ivHexToWordArray(ivHex);
    const ctWA = base64ToWordArray(documentB64);

    if (ctWA.sigBytes % 16 !== 0) {
        throw new Error(
            `Decoded ciphertext is ${ctWA.sigBytes} bytes; must be a multiple of 16 (AES-CBC block size), matching PHP OpenSSL.`
        );
    }

    const decrypted = CryptoJS.AES.decrypt(
        CryptoJS.lib.CipherParams.create({ ciphertext: ctWA }),
        keyWA,
        { iv: ivWA, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.NoPadding }
    );

    const utf8 = decrypted.toString(CryptoJS.enc.Utf8);
    if (utf8.length === 0 && decrypted.sigBytes > 0) {
        throw new Error(
            'Decryption did not yield valid UTF-8 (wrong key or IV, or corrupt ciphertext).'
        );
    }

    return utf8.replace(/[\x00-\x1F\x7F]/g, '').trim();
}

/** Same as PHP encrypt_payload(): OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING. */
function phpStyleEncrypt(plainText, ivHexOrNull) {
    const keyWA = parseKeyHexWordArray();
    let ivWA;
    if (ivHexOrNull && String(ivHexOrNull).trim() !== '') {
        ivWA = ivHexToWordArray(ivHexOrNull);
    } else {
        ivWA = CryptoJS.lib.WordArray.random(16);
    }

    const padded = utf8NullPadToBlock(plainText);
    const plainWA = uint8ToLatin1WordArray(padded);

    const enc = CryptoJS.AES.encrypt(plainWA, keyWA, {
        iv: ivWA,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.NoPadding
    });

    const documentB64 = CryptoJS.enc.Base64.stringify(enc.ciphertext);
    const idHex = CryptoJS.enc.Hex.stringify(ivWA);

    return { id: idHex, document: documentB64 };
}

function formatCaughtError(e) {
    let msg = '';
    if (typeof e === 'string') {
        msg = e;
    } else if (e && typeof e === 'object') {
        const name = typeof e.name === 'string' ? e.name : '';
        const message = typeof e.message === 'string' ? e.message.trim() : '';
        msg = [name, message].filter(Boolean).join(': ').trim();
        if (!msg && typeof e.toString === 'function') {
            const s = e.toString();
            if (s && s !== '[object Object]') {
                msg = s;
            }
        }
    }
    if (!msg) {
        msg = 'Request failed.';
    }
    return msg;
}

submitBtn.addEventListener('click', () => {
    errorBox.style.display = 'none';
    resultBox.style.display = 'none';
    errorBox.textContent = '';

    if (typeof CryptoJS === 'undefined') {
        errorBox.textContent =
            'CryptoJS did not load (offline or blocked CDN). Ensure the crypto-js script runs before script.js.';
        errorBox.style.display = 'block';
        return;
    }

    const isEncrypt = document.querySelector('input[value="encrypt"]').checked;

    try {
        if (isEncrypt) {
            const plaintextEl = document.getElementById('plaintext');
            const ivInputEl = document.getElementById('encrypt_iv');
            const plaintext = plaintextEl.value;
            const ivInput = ivInputEl.value.trim();

            if (!plaintext) {
                throw new Error('Enter plaintext to encrypt');
            }

            const pair = phpStyleEncrypt(plaintext, ivInput !== '' ? ivInput : null);
            const out = JSON.stringify(pair, null, 2);

            if (resultLabel) {
                resultLabel.textContent = 'Encrypted payload (JSON)';
            }
            resultContent.textContent = out;
        } else {
            const payloadEl = document.getElementById('payload');
            const cleaned = removeControlChars(payloadEl.value);
            if (!cleaned) {
                throw new Error('Paste a JSON payload with id and document');
            }

            const obj = JSON.parse(cleaned);
            if (obj.id == null || obj.document == null) {
                throw new Error('JSON must include "id" (IV, hex) and "document" (base64)');
            }

            const text = phpStyleDecrypt(obj.document, obj.id);

            if (resultLabel) {
                resultLabel.textContent = 'Decrypted output';
            }
            try {
                resultContent.textContent = JSON.stringify(JSON.parse(text), null, 2);
            } catch {
                resultContent.textContent = text;
            }
        }

        resultBox.style.display = 'block';
    } catch (e) {
        errorBox.textContent = formatCaughtError(e);
        errorBox.style.display = 'block';
    }
});
