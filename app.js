document.addEventListener('DOMContentLoaded', () => {
    initHeroSimulator();
    initInteractiveSimulator();
    initCodeTabs();
    initCheckout();
});

async function initCheckout() {
    try {
        const baseUrl = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
            ? 'http://localhost:8080'
            : 'https://peter14l-pq-aura-server.hf.space'; // Fallback to Hugging Face Space in production

        const response = await fetch(`${baseUrl}/config`);
        if (!response.ok) throw new Error('Failed to fetch config');
        const config = await response.json();

        // 1. Initialize Razorpay
        loadScript('https://checkout.razorpay.com/v1/checkout.js', () => {
            const razorpayBtn = document.getElementById('btn-pricing-commercial');
            if (razorpayBtn) {
                razorpayBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    const options = {
                        "key": config.razorpay_key_id,
                        "amount": "1650000", // 16500 INR in paise (~$199 USD)
                        "currency": "INR",
                        "name": "PQ-Aura",
                        "description": "Commercial SDK License",
                        "image": "assets/logo.jpg",
                        "handler": function (res) {
                            alert("Payment Successful! Payment ID: " + res.razorpay_payment_id);
                        },
                        "prefill": {
                            "name": "",
                            "email": "",
                            "contact": ""
                        },
                        "theme": {
                            "color": "#6366f1"
                        }
                    };
                    const rzp = new window.Razorpay(options);
                    rzp.open();
                });
            }
        });

    } catch (err) {
        console.error('Failed to initialize checkout:', err);
    }
}

function loadScript(src, callback) {
    const script = document.createElement('script');
    script.src = src;
    script.onload = callback;
    script.onerror = () => console.error('Failed to load script: ' + src);
    document.head.appendChild(script);
}

// ==========================================================================
// 1. Hero Handshake Simulator
// ==========================================================================
function initHeroSimulator() {
    const btn = document.getElementById('btn-run-simulation');
    const output = document.getElementById('console-output');

    if (!btn || !output) return;

    const logLines = [
        { text: "Alice: Loading pre-key bundle for 'bob'...", delay: 200, type: "info" },
        { text: "Server: Pre-key bundle retrieved successfully (1600 bytes).", delay: 800, type: "success" },
        { text: "Alice: Generating local ephemeral key pair (X25519 + ML-KEM-1024)...", delay: 1300, type: "info" },
        { text: "Alice: Performing classical DH exchange (X25519)...", delay: 1800, type: "info" },
        { text: "Alice: Encapsulating post-quantum shared secret (ML-KEM)...", delay: 2200, type: "info" },
        { text: "Alice: Mixing classical & quantum entropy via BLAKE3 KDF...", delay: 2700, type: "info" },
        { text: "Alice: Initial root key derived: 0x8a92f...7b2c9", delay: 3100, type: "success" },
        { text: "Alice: Handshake message encrypted and dispatched to Bob.", delay: 3500, type: "info" },
        { text: "Bob: Handshake message received. Decoding ciphertexts...", delay: 4000, type: "info" },
        { text: "Bob: Decapsulating quantum shared secret...", delay: 4400, type: "info" },
        { text: "Bob: Deriving matching session root key: 0x8a92f...7b2c9", delay: 4900, type: "success" },
        { text: "Double Ratchet Session: SECURE & ACTIVE (Quantum Immune)", delay: 5300, type: "success" }
    ];

    btn.addEventListener('click', () => {
        btn.disabled = true;
        btn.textContent = "Simulating...";
        output.innerHTML = "";

        logLines.forEach((line) => {
            setTimeout(() => {
                const div = document.createElement('div');
                div.className = `console-line text-${line.type}`;
                div.textContent = `> ${line.text}`;
                output.appendChild(div);
                output.scrollTop = output.scrollHeight;

                if (line === logLines[logLines.length - 1]) {
                    btn.disabled = false;
                    btn.textContent = "Run Handshake Simulator";
                }
            }, line.delay);
        });
    });
}

// ==========================================================================
// 2. Step-by-Step Interactive Playroom
// ==========================================================================
function initInteractiveSimulator() {
    // Buttons & Interactive elements
    const stepBtns = document.querySelectorAll('.sim-step-btn');
    const panes = document.querySelectorAll('.sim-pane');

    // Step 1: Generate keys
    const btnGenKeys = document.getElementById('btn-gen-keys');
    const aliceKeyDisplay = document.getElementById('alice-key-display');
    const bobKeyDisplay = document.getElementById('bob-key-display');
    const btnStep2 = document.getElementById('sim-btn-step2');

    // Step 2: Upload bundle
    const btnUploadBundle = document.getElementById('btn-upload-bundle');
    const terminalStep2 = document.getElementById('terminal-step2');
    const btnStep3 = document.getElementById('sim-btn-step3');

    // Step 3: Derive secrets
    const btnDeriveSk = document.getElementById('btn-derive-sk');
    const terminalStep3 = document.getElementById('terminal-step3');
    const btnStep4 = document.getElementById('sim-btn-step4');

    // Step 4: Chat room
    const chatInput = document.getElementById('chat-input-field');
    const chatSendBtn = document.getElementById('chat-send-btn');
    const chatMessages = document.getElementById('chat-messages');

    // Mock keys
    let aliceKeys = null;
    let bobKeys = null;
    let mockRootKey = "";
    
    // Tab switching logic
    stepBtns.forEach((btn) => {
        btn.addEventListener('click', () => {
            const step = btn.getAttribute('data-step');
            
            // Check if step is unlocked
            if (step === '2' && !aliceKeys) return;
            if (step === '3' && (!terminalStep2.innerHTML.includes("success") && !terminalStep2.innerHTML.includes("Uploaded"))) return;
            if (step === '4' && !mockRootKey) return;

            stepBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            panes.forEach(pane => pane.classList.remove('active'));
            document.getElementById(`pane-step${step}`).classList.add('active');
        });
    });

    // Step 1 Click Handler: Generate keys
    btnGenKeys.addEventListener('click', () => {
        aliceKeys = {
            classic: "pk_x25519_alice_" + Math.random().toString(16).substr(2, 16),
            quantum: "pk_mlkem1024_alice_" + Math.random().toString(16).substr(2, 32)
        };
        bobKeys = {
            classic: "pk_x25519_bob_" + Math.random().toString(16).substr(2, 16),
            quantum: "pk_mlkem1024_bob_" + Math.random().toString(16).substr(2, 32)
        };

        aliceKeyDisplay.textContent = `X25519: ${aliceKeys.classic}\nML-KEM: ${aliceKeys.quantum}`;
        bobKeyDisplay.textContent = `X25519: ${bobKeys.classic}\nML-KEM: ${bobKeys.quantum}`;

        btnGenKeys.textContent = "Regenerate Keys";
        btnUploadBundle.disabled = false;
        btnStep2.classList.add('unlocked');
        
        // Auto-navigate to step 2 after a small delay
        setTimeout(() => {
            btnStep2.click();
        }, 1000);
    });

    // Step 2 Click Handler: Upload bundle
    btnUploadBundle.addEventListener('click', () => {
        btnUploadBundle.disabled = true;
        terminalStep2.innerHTML = '<span class="text-info">> Uploading Bob\'s Pre-key Bundle to central server...</span>';
        
        setTimeout(() => {
            const bundleJson = {
                identity_pk: bobKeys.classic,
                signed_pre_key: bobKeys.quantum,
                one_time_pre_key: "ot_kem_bob_" + Math.random().toString(16).substr(2, 16)
            };
            terminalStep2.innerHTML = `
<span class="text-info">> POST /prekey/upload HTTP/1.1</span><br>
<span class="text-info">> Payload: ${JSON.stringify(bundleJson, null, 2)}</span><br>
<span class="text-success">> HTTP/1.1 200 OK (Uploaded successfully)</span>
            `;
            btnDeriveSk.disabled = false;
            btnStep3.classList.add('unlocked');
            
            setTimeout(() => {
                btnStep3.click();
            }, 1200);
        }, 1000);
    });

    // Step 3 Click Handler: Derive keys
    btnDeriveSk.addEventListener('click', () => {
        btnDeriveSk.disabled = true;
        terminalStep3.innerHTML = '<span class="text-info">> Initiating hybrid cryptographic exchanges...</span>';

        setTimeout(() => {
            mockRootKey = "0x" + Math.random().toString(16).substr(2, 16) + Math.random().toString(16).substr(2, 16);
            terminalStep3.innerHTML = `
<span class="text-info">> Classical DH Key (X25519): 32 bytes derived.</span><br>
<span class="text-info">> Quantum Ciphertext (ML-KEM-1024): 1568 bytes encapsulated.</span><br>
<span class="text-info">> Mixing entropy with BLAKE3 KDF...</span><br>
<span class="text-success">> Derived root session key: ${mockRootKey}</span><br>
<span class="text-success">> Alice & Bob ratchet states successfully synchronized.</span>
            `;
            chatInput.disabled = false;
            chatSendBtn.disabled = false;
            btnStep4.classList.add('unlocked');

            setTimeout(() => {
                btnStep4.click();
            }, 1500);
        }, 1200);
    });

    // Step 4: Chat messages
    let ratchetCount = 0;

    chatSendBtn.addEventListener('click', sendChatMessage);
    chatInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendChatMessage();
    });

    function sendChatMessage() {
        const text = chatInput.value.trim();
        if (!text) return;

        chatInput.value = "";
        ratchetCount++;

        // Append Alice's Message
        appendMessage("Alice", text);

        // Generate encrypted packet structure simulation
        const mockCiphertext = "ct_" + Math.random().toString(16).substr(2, 16);
        const packetInfo = {
            header_ciphertext: "hdr_" + Math.random().toString(16).substr(2, 16),
            payload_ciphertext: mockCiphertext,
            ratchet_step: ratchetCount
        };

        const systemDiv = document.createElement('div');
        systemDiv.className = "chat-msg system";
        systemDiv.innerHTML = `
            <strong>Encrypted Packet Dispatched:</strong><br>
            Header: ${packetInfo.header_ciphertext.substr(0, 16)}...<br>
            Payload: ${packetInfo.payload_ciphertext.substr(0, 16)}...<br>
            Ratchet Step: ${packetInfo.ratchet_step} (Forward Secrecy Verified)
        `;
        chatMessages.appendChild(systemDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;

        // Mock Bob's Auto-Response
        setTimeout(() => {
            const bobResponses = [
                "Understood. Initiating next sending ratchet.",
                "Decrypting using shared secret key derived from ML-KEM decapsulation.",
                "Perfect forward secrecy verified. Root key ratcheting forward.",
                "Message received and decrypted safely. Post-quantum immunity active."
            ];
            const responseText = bobResponses[(ratchetCount - 1) % bobResponses.length];
            appendMessage("Bob", responseText);
        }, 1000);
    }

    function appendMessage(sender, text) {
        const div = document.createElement('div');
        div.className = `chat-msg ${sender.toLowerCase()}`;
        div.textContent = `${sender}: ${text}`;
        chatMessages.appendChild(div);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
}

// ==========================================================================
// 3. Code Integration Tabs
// ==========================================================================
function initCodeTabs() {
    const tabHeaders = document.querySelectorAll('.tab-header-btn');
    const tabPanes = document.querySelectorAll('.tab-content-pane');

    tabHeaders.forEach((btn) => {
        btn.addEventListener('click', () => {
            const tabName = btn.getAttribute('data-tab');

            tabHeaders.forEach(h => h.classList.remove('active'));
            btn.classList.add('active');

            tabPanes.forEach(pane => pane.classList.remove('active'));
            document.getElementById(`tab-pane-${tabName}`).classList.add('active');
        });
    });
}
