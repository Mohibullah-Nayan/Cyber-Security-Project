# 🌐 CyberShield • Blockchain Steganography & Forensic Intelligence System

A cutting-edge, portfolio- and university-defense grade cybersecurity platform combining **LSB Image Steganography**, **AES-256-GCM Authenticated Encryption**, **ECDSA Digital Signatures (NIST P-256)**, **Binary Merkle Trees**, **PSNR & SSIM Image Quality Metrics**, **Chi-Square (χ²) Steganalysis**, **Forensic Pixel Heatmaps**, and a **Proof-of-Work Blockchain with P2P Byzantine Consensus Simulation**.

Features a **futuristic cybernetic glassmorphism interface with an interactive rotating 3D holographic digital globe** rendered using real-time HTML5/Canvas math.

---

## 🏛️ System Architecture

```
blockchain_stego/
├── core/
│   ├── __init__.py           # Unified exports
│   ├── crypto_utils.py       # AES-256-GCM, PBKDF2, ECDSA Sign/Verify, PSNR, SSIM, Chi-Square, Shannon Entropy
│   ├── steganography.py      # LSB Stego Engine (Capacity checks, header encoding/decoding)
│   ├── merkle_tree.py        # Cryptographic Binary Merkle Tree & O(log N) Merkle Proofs
│   ├── block.py              # Canonical Block with Merkle Root, Nonce, ECDSA Signature
│   └── blockchain.py         # Distributed Ledger, PoW consensus, P2P BFT voting, verification engine
├── tests/
│   └── test_core.py          # 12 automated unit tests verifying crypto, stego, and tamper detection
├── data/                     # Output directory for carrier images, outputs, and ledger JSON
├── demo_cli.py               # Standalone interactive CLI demonstration
├── tamper_experiment.py      # Automated 1-pixel tamper attack experiment
├── app.py                    # Futuristic Streamlit Web Application with 3D Holographic Globe
├── requirements.txt          # Python dependencies
└── README.md                 # Technical project documentation
```

---

## 🔐 Advanced Cryptographic & Scientific Specifications

| Component | Standard / Metric | Technical Purpose |
| :--- | :--- | :--- |
| **3D Holographic Globe** | HTML5 Canvas / Spherical Math | Rotating vector cyber globe with orbiting telemetry data nodes. |
| **Symmetric Encryption** | AES-256-GCM | Authenticated payload encryption with 16-byte random salt and 16-byte GMAC tag. |
| **Key Derivation** | PBKDF2-HMAC-SHA256 | 100,000 iterations according to NIST SP 800-132 recommendations. |
| **Digital Signatures** | ECDSA (SECP256R1 / NIST P-256) | Sender non-repudiation: signs image SHA-256 hash using elliptic-curve cryptography. |
| **Image Fidelity Metrics** | PSNR ($>40\text{ dB}$) & SSIM ($\approx 1.0$) | Proves mathematically that steganography introduces zero perceptible visual distortion. |
| **Statistical Steganalysis** | Chi-Square ($\chi^2$) PoV Test | Analyzes Pairs of Values ($2k, 2k+1$) to demonstrate stealth against detection. |
| **Data Integrity Trees** | Binary Merkle Tree | Logarithmic $O(\log N)$ Merkle Proofs for batch image verification. |
| **Consensus Engine** | Proof-of-Work (PoW) | Configurable difficulty target requiring hashes to begin with $N$ leading zeros. |
| **Decentralized P2P** | Byzantine Fault Tolerance (BFT) | 4-node global consensus simulator demonstrating 51% majority consensus. |

---

## 🖥️ Streamlit Web Application (6 Cyber Tabs)

1. **📥 1. Embed & Mine Block:**
   - Upload carrier image; calculates capacity & Shannon entropy.
   - Encrypts payload via AES-256-GCM.
   - Computes **PSNR (dB)** and **SSIM** image fidelity scores.
   - Builds **Merkle Tree Root** and signs with **ECDSA Private Key**.
   - Mines block onto the Blockchain with Proof-of-Work.

2. **📤 2. Extract Secret (Zero-Trust Guard):**
   - Candidate stego image extraction.
   - **Zero-Trust Enforcement:** Blocks decryption immediately if candidate image SHA-256 does not match immutable blockchain records!
   - Verifies sender ECDSA digital signature for non-repudiation.

3. **🦹 3. Adversary Tamper Studio:**
   - 🕵️ Stealth 1-Pixel Attack (Invisible to human eyes)
   - 🖍️ Visible Watermark / Drawing Attack
   - ⚡ Random Pixel Noise Injection
   - 🔄 Color Channel Inversion Attack

4. **🚨 4. Forensic Lab & Difference Heatmap:**
   - Audits any candidate image against recorded block records.
   - Generates a **Forensic Pixel Difference Heatmap** highlighting altered pixels.
   - Performs **Chi-Square ($\chi^2$) Steganalysis** and **Shannon Entropy** analysis.
   - Downloads an official **Cryptographic Certificate of Authenticity (JSON)**.

5. **🌐 5. P2P Byzantine Consensus Simulator:**
   - 4 distributed peer nodes (USA, Germany, Japan, Singapore).
   - Demonstrates Byzantine Fault Tolerance when broadcasting genuine vs counterfeit blocks.

6. **🔗 6. Visual Blockchain Graph & Merkle Explorer:**
   - Visual SVG/DAG graph showing connected blocks with glowing arrows and live node statuses.
   - Interactive Merkle Tree Proof verification lab ($O(\log N)$).

---

## 🚀 How to Run

### Run Unit Tests:
```bash
python -m unittest discover -s tests -p "test_*.py"
```

### Launch Web Dashboard:
```bash
streamlit run app.py
```
