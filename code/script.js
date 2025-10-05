document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements ---
    const tabs = {
        additive: document.getElementById('tab-additive'),
        multiplicative: document.getElementById('tab-multiplicative'),
        affine: document.getElementById('tab-affine'),
    };
    const contents = {
        additive: document.getElementById('content-additive'),
        multiplicative: document.getElementById('content-multiplicative'),
        affine: document.getElementById('content-affine'),
    };
    const inputs = {
        text: document.getElementById('text-input'),
        additiveKey: document.getElementById('additive-key'),
        multiplicativeKey: document.getElementById('multiplicative-key'),
        affineKeyA: document.getElementById('affine-key-a'),
        affineKeyB: document.getElementById('affine-key-b'),
    };
    const outputs = {
        text: document.getElementById('text-output'),
        bruteForce: document.getElementById('brute-force-output'),
    };
    const buttons = {
        encrypt: document.getElementById('btn-encrypt'),
        decrypt: document.getElementById('btn-decrypt'),
        bruteForce: document.getElementById('btn-brute-force'),
    };
    const errorMessage = document.getElementById('error-message');

    let activeCipher = 'additive';

    // --- Utility Functions ---
    const ALPHABET_SIZE = 26;
    const COPRIME_KEYS = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];

    // Expanded dictionary (add more words or replace with larger wordlist for best results)
    const ENGLISH_WORDS = new Set([
        'a', 'about', 'all', 'also', 'an', 'and', 'any', 'are', 'as', 'at', 'attack', 'be', 'been', 'but', 'by', 'can', 'cipher',
        'come', 'could', 'danger', 'day', 'do', 'does', 'down', 'each', 'even', 'every', 'for', 'from', 'get', 'give', 'go',
        'good', 'has', 'have', 'he', 'her', 'here', 'him', 'his', 'how', 'i', 'if', 'in', 'into', 'is', 'it', 'its', 'just',
        'know', 'like', 'look', 'make', 'man', 'many', 'me', 'meet', 'message', 'more', 'most', 'my', 'new', 'no', 'not', 'now',
        'of', 'on', 'one', 'only', 'or', 'other', 'our', 'out', 'over', 'people', 'say', 'secret', 'secure', 'see', 'she', 'so',
        'some', 'take', 'tell', 'than', 'that', 'the', 'their', 'them', 'then', 'there', 'these', 'they', 'thing', 'think', 'this',
        'those', 'time', 'to', 'two', 'up', 'us', 'use', 'very', 'want', 'was', 'we', 'well', 'were', 'what', 'when', 'which',
        'who', 'will', 'with', 'word', 'work', 'would', 'year', 'yes', 'you', 'your',
        // longer / more specific words that help with plausibility detection:
        'message', 'communication', 'encryption', 'decryption', 'plaintext', 'ciphertext', 'security', 'example',
        'multiplicative', 'additive', 'affine', 'attackers', 'programming', 'information', 'secretmessage', 'dangerous',
        'password', 'authenticate', 'authentication'
    ]);

    const mod = (n, m) => ((n % m) + m) % m;

    const modInverse = (a, m) => {
        a = mod(a, m);
        for (let x = 1; x < m; x++) {
            if (mod(a * x, m) === 1) {
                return x;
            }
        }
        return 1; // fallback (shouldn't be used for valid coprime a)
    };

    const isCoprime = (num) => COPRIME_KEYS.includes(num);

    const displayError = (msg) => {
        errorMessage.textContent = msg;
        setTimeout(() => errorMessage.textContent = '', 3000);
    };

    /**
     * Checks whether the array of words contains at least one English dictionary
     * word of length >= minLongLength. This helps detect valid-looking long words.
     */
    const hasLongDictionaryWord = (words, minLongLength = 6) => {
        for (const w of words) {
            if (w.length >= minLongLength && ENGLISH_WORDS.has(w)) return true;
        }
        return false;
    };

    /**
     * Checks if a given text is plausible English by checking:
     *  - percentage of words in the small dictionary
     *  - or presence of at least one long dictionary word (>=6 chars)
     *  - for very short texts, require at least one dictionary match
     */
    const isPlausibleEnglish = (text) => {
        const words = text.toLowerCase().replace(/[^a-z\s]/g, '').split(/\s+/).filter(w => w.length > 0);
        if (words.length === 0) return false;

        let matchCount = 0;
        for (const word of words) {
            if (ENGLISH_WORDS.has(word)) matchCount++;
        }

        // If any long dictionary word exists, treat as plausible immediately.
        if (hasLongDictionaryWord(words, 6)) return true;

        // Heuristic fallback rules:
        // - For very short texts (1-2 words), at least one dictionary match is required.
        // - For longer texts, require at least 50% dictionary match.
        if (words.length <= 2) {
            return matchCount > 0;
        } else {
            return (matchCount > 0) && (matchCount / words.length >= 0.5);
        }
    };

    // --- Cipher Logic ---
    const processText = (text, keyA, keyB, isDecrypt) => {
        if (isDecrypt) {
            const invA = modInverse(keyA, ALPHABET_SIZE);
            return text.split('').map(char => {
                const charCode = char.charCodeAt(0);
                if (char >= 'a' && char <= 'z') {
                    let processedCode = mod(invA * (charCode - 'a'.charCodeAt(0) - keyB), ALPHABET_SIZE);
                    return String.fromCharCode(processedCode + 'a'.charCodeAt(0));
                } else if (char >= 'A' && char <= 'Z') {
                    let processedCode = mod(invA * (charCode - 'A'.charCodeAt(0) - keyB), ALPHABET_SIZE);
                    return String.fromCharCode(processedCode + 'A'.charCodeAt(0));
                }
                return char;
            }).join('');
        } else {
            return text.split('').map(char => {
                const charCode = char.charCodeAt(0);
                if (char >= 'a' && char <= 'z') {
                    let processedCode = mod(keyA * (charCode - 'a'.charCodeAt(0)) + keyB, ALPHABET_SIZE);
                    return String.fromCharCode(processedCode + 'a'.charCodeAt(0));
                } else if (char >= 'A' && char <= 'Z') {
                    let processedCode = mod(keyA * (charCode - 'A'.charCodeAt(0)) + keyB, ALPHABET_SIZE);
                    return String.fromCharCode(processedCode + 'A'.charCodeAt(0));
                }
                return char;
            }).join('');
        }
    };

    // --- Copy Button UI Setup (creates a small copy button next to the output) ---
    // We will append a small absolutely-positioned button inside the same container as outputs.text.
    // This code expects that outputs.text is a <textarea> or input element inside the document.
    const createCopyButton = () => {
        // Create wrapper if needed to position button
        const outEl = outputs.text;
        const wrapper = document.createElement('div');
        wrapper.style.position = 'relative';
        wrapper.style.display = 'inline-block';
        wrapper.style.width = outEl.style.width || (outEl.offsetWidth ? outEl.offsetWidth + 'px' : '100%');

        // Insert wrapper before outEl and move outEl inside wrapper
        outEl.parentNode.insertBefore(wrapper, outEl);
        wrapper.appendChild(outEl);

        // style the textarea to take full width of wrapper
        outEl.style.boxSizing = 'border-box';
        outEl.style.width = '100%';

        // create the button
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.id = 'btn-copy-output';
        btn.setAttribute('aria-label', 'Copy output to clipboard');
        btn.title = 'Copy to clipboard';
        btn.style.position = 'absolute';
        btn.style.right = '8px';
        btn.style.top = '8px';
        btn.style.width = '36px';
        btn.style.height = '36px';
        btn.style.border = 'none';
        btn.style.borderRadius = '6px';
        btn.style.display = 'flex';
        btn.style.alignItems = 'center';
        btn.style.justifyContent = 'center';
        btn.style.cursor = 'pointer';
        btn.style.background = 'rgba(0,0,0,0.04)';
        btn.style.backdropFilter = 'blur(2px)';
        btn.style.transition = 'background 120ms ease, transform 100ms ease';
        btn.style.padding = '4px';
        btn.style.outline = 'none';

        // SVG copy icon
        const copySVG = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
            <path d="M16 1H4C2.89543 1 2 1.89543 2 3V15" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            <rect x="8" y="5" width="14" height="14" rx="2" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>`;

        // Check mark SVG (shown briefly after copy)
        const checkSVG = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
            <path d="M20 6L9 17L4 12" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>`;

        btn.innerHTML = copySVG;

        // keyboard interaction: Enter / Space should trigger click
        btn.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                btn.click();
            }
        });

        // click behavior
        btn.addEventListener('click', async () => {
            const textToCopy = outputs.text.value || outputs.text.innerText || '';
            if (!textToCopy) {
                // small shake to indicate nothing to copy
                btn.style.transform = 'translateX(-2px)';
                setTimeout(() => btn.style.transform = '', 120);
                return;
            }
            try {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    await navigator.clipboard.writeText(textToCopy);
                } else {
                    // fallback
                    const textarea = document.createElement('textarea');
                    textarea.value = textToCopy;
                    textarea.style.position = 'fixed';
                    textarea.style.left = '-9999px';
                    document.body.appendChild(textarea);
                    textarea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textarea);
                }

                // visual feedback: show checkmark for a short time
                btn.innerHTML = checkSVG;
                btn.style.background = 'rgba(0,128,0,0.12)';
                setTimeout(() => {
                    btn.innerHTML = copySVG;
                    btn.style.background = 'rgba(0,0,0,0.04)';
                }, 1200);
            } catch (err) {
                console.error('Copy failed', err);
                displayError('Copy failed');
            }
        });

        // hover styles
        btn.addEventListener('mouseover', () => btn.style.background = 'rgba(0,0,0,0.08)');
        btn.addEventListener('mouseout', () => btn.style.background = 'rgba(0,0,0,0.04)');

        wrapper.appendChild(btn);
    };

    // Create copy button once
    createCopyButton();

    // --- Event Handlers ---
    const handleEncrypt = () => {
        const text = inputs.text.value;
        if (!text) return displayError('Input text cannot be empty.');

        let result = '';
        try {
            switch (activeCipher) {
                case 'additive':
                    const addKey = parseInt(inputs.additiveKey.value);
                    if (isNaN(addKey)) return displayError('Additive key is missing or invalid.');
                    result = processText(text, 1, addKey, false);
                    break;
                case 'multiplicative':
                    const mulKey = parseInt(inputs.multiplicativeKey.value);
                    if (isNaN(mulKey) || !isCoprime(mulKey)) return displayError('Multiplicative key must be coprime to 26.');
                    result = processText(text, mulKey, 0, false);
                    break;
                case 'affine':
                    const affKeyA = parseInt(inputs.affineKeyA.value);
                    const affKeyB = parseInt(inputs.affineKeyB.value);
                    if (isNaN(affKeyA) || !isCoprime(affKeyA)) return displayError('Key A must be coprime to 26.');
                    if (isNaN(affKeyB)) return displayError('Key B is missing or invalid.');
                    result = processText(text, affKeyA, affKeyB, false);
                    break;
            }
            outputs.text.value = result;
            outputs.bruteForce.innerHTML = '';
        } catch (e) {
            displayError('An error occurred during encryption.');
            console.error(e);
        }
    };

    const handleDecrypt = () => {
        const text = inputs.text.value;
        if (!text) return displayError('Input text cannot be empty.');

        let result = '';
        try {
            switch (activeCipher) {
                case 'additive':
                    const addKey = parseInt(inputs.additiveKey.value);
                    if (isNaN(addKey)) return displayError('Additive key is missing or invalid.');
                    result = processText(text, 1, addKey, true);
                    break;
                case 'multiplicative':
                    const mulKey = parseInt(inputs.multiplicativeKey.value);
                    if (isNaN(mulKey) || !isCoprime(mulKey)) return displayError('Multiplicative key must be coprime to 26.');
                    result = processText(text, mulKey, 0, true);
                    break;
                case 'affine':
                    const affKeyA = parseInt(inputs.affineKeyA.value);
                    const affKeyB = parseInt(inputs.affineKeyB.value);
                    if (isNaN(affKeyA) || !isCoprime(affKeyA)) return displayError('Key A must be coprime to 26.');
                    if (isNaN(affKeyB)) return displayError('Key B is missing or invalid.');
                    result = processText(text, affKeyA, affKeyB, true);
                    break;
            }
            outputs.text.value = result;
            outputs.bruteForce.innerHTML = '';
        } catch (e) {
            displayError('An error occurred during decryption.');
            console.error(e);
        }
    };

    const handleBruteForce = () => {
        const text = inputs.text.value;
        if (!text) return displayError('Input text cannot be empty.');

        outputs.bruteForce.innerHTML = '';
        outputs.text.value = '';

        const plausibleResults = [];

        const tryCandidate = (keyLabel, decryptedText) => {
            if (isPlausibleEnglish(decryptedText)) {
                plausibleResults.push({ key: keyLabel, text: decryptedText });
            }
        };

        switch (activeCipher) {
            case 'additive':
                for (let k = 0; k < ALPHABET_SIZE; k++) {
                    const decrypted = processText(text, 1, k, true);
                    tryCandidate(`Key ${k}`, decrypted);
                }
                break;
            case 'multiplicative':
                COPRIME_KEYS.forEach(k => {
                    const decrypted = processText(text, k, 0, true);
                    tryCandidate(`Key ${k}`, decrypted);
                });
                break;
            case 'affine':
                COPRIME_KEYS.forEach(k_a => {
                    for (let k_b = 0; k_b < ALPHABET_SIZE; k_b++) {
                        const decrypted = processText(text, k_a, k_b, true);
                        tryCandidate(`Key (${k_a}, ${k_b})`, decrypted);
                    }
                });
                break;
        }

        if (plausibleResults.length === 0) {
            // No plausible results found by heuristics -> show all possibilities (as before)
            outputs.text.value = "No plausible English text found. See all possibilities below.";
            let resultsHTML = '<div class="text-center text-gray-400 mb-2">No plausible English decryption found. Displaying all possibilities.</div>';
            switch (activeCipher) {
                case 'additive':
                    for (let k = 0; k < ALPHABET_SIZE; k++) {
                        resultsHTML += `<div class="brute-force-result"><b>Key ${k}:</b> ${processText(text, 1, k, true)}</div>`;
                    }
                    break;
                case 'multiplicative':
                    COPRIME_KEYS.forEach(k => {
                        resultsHTML += `<div class="brute-force-result"><b>Key ${k}:</b> ${processText(text, k, 0, true)}</div>`;
                    });
                    break;
                case 'affine':
                    COPRIME_KEYS.forEach(k_a => {
                        for (let k_b = 0; k_b < ALPHABET_SIZE; k_b++) {
                            resultsHTML += `<div class="brute-force-result"><b>Key (${k_a}, ${k_b}):</b> ${processText(text, k_a, k_b, true)}</div>`;
                        }
                    });
                    break;
            }
            outputs.bruteForce.innerHTML = resultsHTML;
        } else {
            // If plausible results are found, display them in the main output field and also detail them.
            // Remove duplicates while preserving order:
            const seen = new Set();
            const uniqueResults = [];
            for (const r of plausibleResults) {
                const signature = r.key + '||' + r.text;
                if (!seen.has(signature)) {
                    seen.add(signature);
                    uniqueResults.push(r);
                }
            }

            // Put labelled results (each candidate separated)
            const labelled = uniqueResults.map(r => `(${r.key}) ${r.text}`).join('\n\n---\n\n');
            outputs.text.value = labelled;

            outputs.bruteForce.innerHTML = uniqueResults.map(result =>
                `<div class="brute-force-result"><b>${result.key}:</b> ${result.text}</div>`
            ).join('');
        }
    };

    // --- Tab Switching Logic ---
    Object.keys(tabs).forEach(tabName => {
        tabs[tabName].addEventListener('click', () => {
            activeCipher = tabName;
            Object.values(tabs).forEach(t => t.classList.remove('active'));
            Object.values(contents).forEach(c => c.classList.add('hidden'));
            tabs[tabName].classList.add('active');
            contents[tabName].classList.remove('hidden');
            // Clear outputs on tab switch
            outputs.text.value = '';
            outputs.bruteForce.innerHTML = '';
            errorMessage.textContent = '';
        });
    });

    // --- Attach Event Listeners ---
    buttons.encrypt.addEventListener('click', handleEncrypt);
    buttons.decrypt.addEventListener('click', handleDecrypt);
    buttons.bruteForce.addEventListener('click', handleBruteForce);
});
