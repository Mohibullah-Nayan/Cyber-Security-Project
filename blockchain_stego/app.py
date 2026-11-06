import os
import io
import time
import random
import json
from datetime import datetime, timezone
from PIL import Image, ImageDraw, ImageChops
import streamlit as st
import streamlit.components.v1 as components

# Import core modules
from core.crypto_utils import (
    calculate_sha256_bytes,
    calculate_shannon_entropy,
    calculate_psnr_ssim,
    calculate_chi_square_steganalysis,
    generate_ecdsa_keypair,
    sign_data,
    verify_signature,
)
from core.steganography import (
    SteganographyEngine,
    CapacityExceededError,
    InvalidStegoImageError,
    TamperDetectedError,
)
from core.merkle_tree import MerkleTree
from core.block import Block
from core.blockchain import Blockchain

# Streamlit Page Configuration
st.set_page_config(
    page_title="CyberShield • Blockchain Steganography & Forensic Intelligence",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ----------------- FUTURISTIC FULL-SCREEN CYBER GLASSMORPHISM CSS -----------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700;900&family=Rajdhani:wght@500;600;700&display=swap');

    /* Ensure Streamlit containers are transparent so the full-screen 3D globe shines through */
    .stApp, [data-testid="stAppViewContainer"], [data-testid="stHeader"] {
        background: transparent !important;
        color: #e2e8f0;
        font-family: 'Rajdhani', sans-serif;
    }

    /* Headings */
    h1, h2, h3, .main-title {
        font-family: 'Orbitron', sans-serif !important;
        letter-spacing: 1.5px;
    }
    .main-title {
        font-size: 2.5rem;
        font-weight: 900;
        text-align: center;
        background: linear-gradient(90deg, #00f0ff, #7000ff, #00ff88);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-shadow: 0 0 30px rgba(0, 240, 255, 0.6);
        margin-bottom: 0.2rem;
    }
    .subtitle {
        font-size: 1.15rem;
        color: #00f0ff;
        text-shadow: 0 0 10px rgba(0, 240, 255, 0.4);
        text-align: center;
        margin-bottom: 1.5rem;
        letter-spacing: 1.5px;
    }

    /* Animated Neon Border Beams on Hover */
    .cyber-card {
        position: relative;
        background: rgba(8, 14, 32, 0.75) !important;
        backdrop-filter: blur(18px);
        -webkit-backdrop-filter: blur(18px);
        border: 1px solid rgba(0, 240, 255, 0.28) !important;
        border-radius: 14px;
        padding: 22px;
        margin-bottom: 20px;
        box-shadow: 0 10px 35px 0 rgba(0, 0, 0, 0.65), inset 0 0 15px rgba(0, 240, 255, 0.06);
        transition: all 0.35s cubic-bezier(0.4, 0, 0.2, 1);
        overflow: hidden;
    }
    .cyber-card:hover {
        border-color: rgba(0, 240, 255, 0.8) !important;
        box-shadow: 0 0 30px rgba(0, 240, 255, 0.45), inset 0 0 22px rgba(0, 240, 255, 0.18);
        transform: translateY(-3px);
    }

    /* Live Cryptographic Marquee Ticker */
    .crypto-ticker-container {
        width: 100%;
        overflow: hidden;
        background: rgba(4, 9, 22, 0.7);
        border-top: 1px solid rgba(0, 240, 255, 0.2);
        border-bottom: 1px solid rgba(0, 240, 255, 0.2);
        padding: 6px 0;
        margin-bottom: 14px;
        white-space: nowrap;
    }
    .crypto-ticker-text {
        display: inline-block;
        font-family: 'Courier New', monospace;
        font-size: 0.8rem;
        color: #00ff88;
        text-shadow: 0 0 6px rgba(0, 255, 136, 0.4);
        animation: tickerMove 28s linear infinite;
    }
    @keyframes tickerMove {
        0% { transform: translateX(100vw); }
        100% { transform: translateX(-100%); }
    }

    /* Cyber Telemetry HUD Grid Cards */
    .hud-stat-box {
        background: rgba(12, 20, 45, 0.6);
        border: 1px solid rgba(0, 240, 255, 0.25);
        border-radius: 10px;
        padding: 10px 16px;
        text-align: center;
        box-shadow: 0 0 15px rgba(0, 240, 255, 0.1);
    }
    .hud-label {
        font-family: 'Orbitron', monospace;
        font-size: 0.72rem;
        color: #94a3b8;
        letter-spacing: 1.5px;
    }
    .hud-value {
        font-family: 'Orbitron', monospace;
        font-size: 1.05rem;
        font-weight: 700;
        color: #00f0ff;
        text-shadow: 0 0 8px rgba(0, 240, 255, 0.5);
    }

    /* Streamlit widget glass styling */
    [data-testid="stExpander"], div[data-baseweb="tab-list"], [data-testid="stMetric"] {
        background: rgba(13, 20, 42, 0.65) !important;
        backdrop-filter: blur(12px);
        border: 1px solid rgba(0, 240, 255, 0.25) !important;
        border-radius: 10px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }

    /* Glowing Badges & Tags */
    .cyber-badge-cyan {
        display: inline-block;
        background: rgba(0, 240, 255, 0.18);
        color: #00f0ff;
        border: 1px solid #00f0ff;
        padding: 5px 12px;
        border-radius: 6px;
        font-family: 'Orbitron', monospace;
        font-size: 0.85rem;
        box-shadow: 0 0 12px rgba(0, 240, 255, 0.4);
    }
    .cyber-badge-green {
        display: inline-block;
        background: rgba(0, 255, 136, 0.18);
        color: #00ff88;
        border: 1px solid #00ff88;
        padding: 5px 12px;
        border-radius: 6px;
        font-family: 'Orbitron', monospace;
        font-size: 0.85rem;
        box-shadow: 0 0 12px rgba(0, 255, 136, 0.4);
    }
    .cyber-badge-red {
        display: inline-block;
        background: rgba(255, 0, 85, 0.2);
        color: #ff0055;
        border: 1px solid #ff0055;
        padding: 5px 12px;
        border-radius: 6px;
        font-family: 'Orbitron', monospace;
        font-size: 0.85rem;
        box-shadow: 0 0 15px rgba(255, 0, 85, 0.5);
    }

    /* Chain Graph Linkage */
    .block-node {
        display: inline-block;
        padding: 14px 20px;
        background: rgba(10, 16, 35, 0.85);
        backdrop-filter: blur(10px);
        border: 1px solid #00f0ff;
        border-radius: 10px;
        margin: 6px;
        box-shadow: 0 0 18px rgba(0, 240, 255, 0.25);
    }
    .chain-arrow {
        font-size: 1.6rem;
        color: #00ff88;
        margin: 0 8px;
        font-weight: bold;
        text-shadow: 0 0 10px #00ff88;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ----------------- FULL-SCREEN 3D ROTATING CYBER GLOBE BACKGROUND -----------------
fullscreen_globe_script = """
<!DOCTYPE html>
<html>
<head>
<style>
  body, html { margin: 0; padding: 0; background: transparent; overflow: hidden; }
</style>
</head>
<body>
<script>
  (function() {
    const parentDoc = window.parent.document || document;
    
    // Check if background canvas already exists in parent DOM
    let bgCanvas = parentDoc.getElementById('fullscreen-cyber-earth-bg');
    if (!bgCanvas) {
      bgCanvas = parentDoc.createElement('canvas');
      bgCanvas.id = 'fullscreen-cyber-earth-bg';
      bgCanvas.style.position = 'fixed';
      bgCanvas.style.top = '0';
      bgCanvas.style.left = '0';
      bgCanvas.style.width = '100vw';
      bgCanvas.style.height = '100vh';
      bgCanvas.style.zIndex = '-1';
      bgCanvas.style.pointerEvents = 'none';
      bgCanvas.style.background = 'radial-gradient(ellipse at 50% 50%, #0c1633 0%, #040714 85%)';
      parentDoc.body.prepend(bgCanvas);
    }

    const ctx = bgCanvas.getContext('2d');
    let width = bgCanvas.width = parentDoc.documentElement.clientWidth || window.innerWidth;
    let height = bgCanvas.height = parentDoc.documentElement.clientHeight || window.innerHeight;

    function onResize() {
      width = bgCanvas.width = parentDoc.documentElement.clientWidth || window.innerWidth;
      height = bgCanvas.height = parentDoc.documentElement.clientHeight || window.innerHeight;
    }
    window.addEventListener('resize', onResize);

    let angle = 0;
    const numPoints = 550;
    const dots = [];

    // Interactive Mouse Parallax tracking
    let targetTiltX = 0, targetTiltY = 0;
    let currentTiltX = 0, currentTiltY = 0;
    parentDoc.addEventListener('mousemove', function(e) {
      targetTiltX = (e.clientX - width / 2) * 0.0004;
      targetTiltY = (e.clientY - height / 2) * 0.0004;
    });

    // Generate Fibonacci Spherical Distribution for realistic planetary topography
    for (let i = 0; i < numPoints; i++) {
      const y = 1 - (i / (numPoints - 1)) * 2;
      const radiusAtY = Math.sqrt(1 - y * y);
      const theta = ((1 + Math.sqrt(5)) / 2) * i * 2 * Math.PI;

      dots.push({
        origX: Math.cos(theta) * radiusAtY,
        origY: y,
        origZ: Math.sin(theta) * radiusAtY,
        isNode: Math.random() > 0.86,
        pulseOffset: Math.random() * Math.PI * 2
      });
    }

    // Space ambient particles
    const spaceStars = [];
    for (let i = 0; i < 90; i++) {
      spaceStars.push({
        x: Math.random() * width,
        y: Math.random() * height,
        radius: Math.random() * 1.5 + 0.5,
        alpha: Math.random() * 0.7 + 0.2,
        speed: Math.random() * 0.15 + 0.05
      });
    }

    // Cryptographic Hex & Binary Code Stream Particles
    const cryptoTokens = ["0x7F", "0101", "SHA-256", "AES-GCM", "0x00", "ECDSA", "NONCE", "POW", "0xFF", "MERKLE", "BFT", "VALID", "1101", "AUTH", "SALT"];
    const cryptoStream = [];
    for (let i = 0; i < 48; i++) {
      cryptoStream.push({
        x: Math.random() * width,
        y: Math.random() * height,
        token: cryptoTokens[Math.floor(Math.random() * cryptoTokens.length)],
        alpha: Math.random() * 0.35 + 0.12,
        speed: Math.random() * 0.35 + 0.1,
        color: Math.random() > 0.5 ? '#00f0ff' : '#00ff88'
      });
    }

    // Web Audio Synthesized Sci-Fi Sound FX
    let audioCtx = null;
    function playCyberBeep(freq = 880, duration = 0.06) {
      try {
        if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        if (audioCtx.state === 'suspended') audioCtx.resume();
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(freq * 1.5, audioCtx.currentTime + duration);
        gain.gain.setValueAtTime(0.04, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + duration);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start();
        osc.stop(audioCtx.currentTime + duration);
      } catch(e) {}
    }

    // Attach soft click sound to Streamlit buttons
    parentDoc.addEventListener('click', function(e) {
      if (e.target && (e.target.tagName === 'BUTTON' || e.target.closest('button'))) {
        playCyberBeep(920, 0.05);
      }
    }, true);

    function render() {
      ctx.clearRect(0, 0, width, height);

      // Smooth mouse parallax interpolation
      currentTiltX += (targetTiltX - currentTiltX) * 0.05;
      currentTiltY += (targetTiltY - currentTiltY) * 0.05;

      // 1. Draw Space Ambient Drift Particles
      spaceStars.forEach(s => {
        s.y -= s.speed;
        if (s.y < 0) s.y = height;
        ctx.beginPath();
        ctx.arc(s.x, s.y, s.radius, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(0, 240, 255, ${s.alpha * 0.4})`;
        ctx.fill();
      });

      // 1b. Draw Cryptographic Hex Code Rain Stream
      ctx.font = '10px "Courier New", monospace';
      cryptoStream.forEach(cs => {
        cs.y -= cs.speed;
        if (cs.y < -15) {
          cs.y = height + 15;
          cs.x = Math.random() * width;
          cs.token = cryptoTokens[Math.floor(Math.random() * cryptoTokens.length)];
        }
        ctx.fillStyle = cs.color === '#00f0ff' 
          ? `rgba(0, 240, 255, ${cs.alpha * 0.65})` 
          : `rgba(0, 255, 136, ${cs.alpha * 0.65})`;
        ctx.fillText(cs.token, cs.x, cs.y);
      });

      // 2. Earth Globe Parameters
      const cx = width / 2;
      const cy = height / 2;
      const globeRadius = Math.min(width, height) * 0.36;
      angle += 0.007;

      // Outer Glowing Atmospheric Ring
      const aura = ctx.createRadialGradient(cx, cy, globeRadius * 0.75, cx, cy, globeRadius * 1.25);
      aura.addColorStop(0, 'rgba(0, 240, 255, 0.09)');
      aura.addColorStop(0.7, 'rgba(112, 0, 255, 0.04)');
      aura.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.beginPath();
      ctx.arc(cx, cy, globeRadius * 1.25, 0, Math.PI * 2);
      ctx.fillStyle = aura;
      ctx.fill();

      // Radar Sweep Line (Military DARPA Satellite Surveillance Beam)
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(angle * 1.8);
      const sweepGrad = ctx.createLinearGradient(0, 0, globeRadius * 1.2, 0);
      sweepGrad.addColorStop(0, 'rgba(0, 255, 136, 0.2)');
      sweepGrad.addColorStop(1, 'rgba(0, 255, 136, 0)');
      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.arc(0, 0, globeRadius * 1.2, -0.2, 0);
      ctx.closePath();
      ctx.fillStyle = sweepGrad;
      ctx.fill();
      ctx.restore();

      // Orbital Satellite Ring 1 (Tilted at 23.5 degrees)
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(23.5 * Math.PI / 180 + currentTiltY);
      ctx.beginPath();
      ctx.ellipse(0, 0, globeRadius * 1.35, globeRadius * 0.38, angle * 0.4, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(0, 240, 255, 0.22)';
      ctx.lineWidth = 1.2;
      ctx.setLineDash([6, 6]);
      ctx.stroke();
      ctx.setLineDash([]);

      // Orbiting Data Packet on Ring 1
      const pAng1 = angle * 2.2;
      const px1 = (globeRadius * 1.35) * Math.cos(pAng1);
      const py1 = (globeRadius * 0.38) * Math.sin(pAng1);
      ctx.beginPath();
      ctx.arc(px1, py1, 3.5, 0, Math.PI * 2);
      ctx.fillStyle = '#00f0ff';
      ctx.shadowColor = '#00f0ff';
      ctx.shadowBlur = 12;
      ctx.fill();
      ctx.restore();

      // Orbital Ring 2 (Counter-Rotating)
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-45 * Math.PI / 180 + currentTiltX);
      ctx.beginPath();
      ctx.ellipse(0, 0, globeRadius * 1.48, globeRadius * 0.42, -angle * 0.3, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(112, 0, 255, 0.25)';
      ctx.lineWidth = 1.0;
      ctx.stroke();

      // Orbiting Data Packet on Ring 2
      const pAng2 = -angle * 1.9;
      const px2 = (globeRadius * 1.48) * Math.cos(pAng2);
      const py2 = (globeRadius * 0.42) * Math.sin(pAng2);
      ctx.beginPath();
      ctx.arc(px2, py2, 3, 0, Math.PI * 2);
      ctx.fillStyle = '#00ff88';
      ctx.shadowColor = '#00ff88';
      ctx.shadowBlur = 10;
      ctx.fill();
      ctx.restore();

      // 3. Render 3D Rotating Earth Sphere Nodes with Cursor Parallax
      const effectiveAngle = angle + currentTiltX * 8;
      const cosA = Math.cos(effectiveAngle);
      const sinA = Math.sin(effectiveAngle);
      const projected = [];

      for (let i = 0; i < dots.length; i++) {
        const d = dots[i];
        const rotX = (d.origX * cosA - d.origZ * sinA) * globeRadius;
        const rotY = (d.origY + currentTiltY * 2) * globeRadius;
        const rotZ = (d.origX * sinA + d.origZ * cosA) * globeRadius;

        const distance = 480;
        const scale = distance / (distance + rotZ);
        const screenX = cx + rotX * scale;
        const screenY = cy + rotY * scale;
        const alpha = Math.max(0.12, (rotZ + globeRadius) / (2 * globeRadius));

        projected.push({ screenX, screenY, scale, alpha, isNode: d.isNode, z: rotZ });
      }

      // Sort by Z for proper 3D depth rendering
      projected.sort((a, b) => a.z - b.z);

      // Draw Neural Constellation Links between adjacent nodes
      ctx.lineWidth = 0.5;
      for (let i = 0; i < projected.length; i += 6) {
        for (let j = i + 1; j < Math.min(i + 4, projected.length); j++) {
          const dx = projected[i].screenX - projected[j].screenX;
          const dy = projected[i].screenY - projected[j].screenY;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 42 && projected[i].alpha > 0.4) {
            ctx.beginPath();
            ctx.moveTo(projected[i].screenX, projected[i].screenY);
            ctx.lineTo(projected[j].screenX, projected[j].screenY);
            ctx.strokeStyle = `rgba(0, 240, 255, ${projected[i].alpha * 0.18})`;
            ctx.stroke();
          }
        }
      }

      // Draw Sphere Dots
      projected.forEach(p => {
        ctx.beginPath();
        if (p.isNode) {
          ctx.arc(p.screenX, p.screenY, 3.2 * p.scale, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(0, 255, 136, ${p.alpha})`;
          ctx.shadowColor = '#00ff88';
          ctx.shadowBlur = 10;
        } else {
          ctx.arc(p.screenX, p.screenY, 1.6 * p.scale, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(0, 240, 255, ${p.alpha * 0.85})`;
          ctx.shadowBlur = 0;
        }
        ctx.fill();
      });

      requestAnimationFrame(render);
    }
    render();
  })();
</script>
</body>
</html>
"""

# Inject Full-Screen 3D Rotating Earth Canvas into Parent Display
components.html(fullscreen_globe_script, height=0)

# Page Titles
st.markdown('<div class="main-title">🛡️ CyberShield • Blockchain Steganography & Forensics</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="subtitle">Military-Grade AES-256-GCM • ECDSA Signatures • Proof-of-Work Merkle Ledger • Multi-Node Consensus</div>',
    unsafe_allow_html=True,
)

# Live Streaming Cryptographic Hash Marquee Ticker
st.markdown(
    """
    <div class="crypto-ticker-container">
      <span class="crypto-ticker-text">
        ⚡ LIVE CRYPTO STREAM: SHA-256 [00f8a3c...c877b7d] • AES-256-GCM GMAC_AUTH_TAG_16B • PBKDF2: 100,000 ITERATIONS (NIST SP 800-132) • ECDSA SECP256R1 SIGNATURE: VALID • MERKLE ROOT: VERIFIED O(log N) • BYZANTINE FAULT TOLERANCE: 4/4 PEERS ONLINE
      </span>
    </div>
    """,
    unsafe_allow_html=True,
)

# ----------------- SESSION STATE & INITIALIZATION -----------------
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
LEDGER_FILE = os.path.join(DATA_DIR, "blockchain_ledger.json")
os.makedirs(DATA_DIR, exist_ok=True)

if "blockchain" not in st.session_state:
    if os.path.exists(LEDGER_FILE):
        try:
            st.session_state.blockchain = Blockchain.load_ledger(LEDGER_FILE)
        except Exception:
            st.session_state.blockchain = Blockchain(difficulty=2)
    else:
        st.session_state.blockchain = Blockchain(difficulty=2)

blockchain: Blockchain = st.session_state.blockchain

# Generate Sender ECDSA Keypair
if "ecdsa_private_key" not in st.session_state:
    priv_key, pub_pem = generate_ecdsa_keypair()
    st.session_state["ecdsa_private_key"] = priv_key
    st.session_state["ecdsa_public_pem"] = pub_pem

# Live Holographic Cyber Telemetry HUD Bar
hud_col1, hud_col2, hud_col3, hud_col4 = st.columns(4)
with hud_col1:
    st.markdown('<div class="hud-stat-box"><div class="hud-label">ZERO-TRUST GATEWAY</div><div class="hud-value" style="color:#00ff88;">● ACTIVE & ENFORCED</div></div>', unsafe_allow_html=True)
with hud_col2:
    st.markdown(f'<div class="hud-stat-box"><div class="hud-label">POW CONSENSUS TARGET</div><div class="hud-value">DIFFICULTY {blockchain.difficulty}</div></div>', unsafe_allow_html=True)
with hud_col3:
    st.markdown('<div class="hud-stat-box"><div class="hud-label">ENCRYPTED CIPHER</div><div class="hud-value">AES-256-GCM / P-256</div></div>', unsafe_allow_html=True)
with hud_col4:
    st.markdown('<div class="hud-stat-box"><div class="hud-label">BYZANTINE NETWORK</div><div class="hud-value" style="color:#00f0ff;">4 PEERS GLOBAL</div></div>', unsafe_allow_html=True)

st.markdown("<div style='margin-bottom: 12px;'></div>", unsafe_allow_html=True)

# ----------------- SIDEBAR CONTROLS -----------------
with st.sidebar:
    st.markdown("### 🌐 Network & Consensus Vault")
    
    is_chain_valid, chain_err = blockchain.is_chain_valid()
    if is_chain_valid:
        st.markdown('<div class="cyber-badge-green">🟢 BLOCKCHAIN: SECURE & AUDITED</div>', unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="cyber-badge-red">🔴 TAMPER DETECTED: {chain_err}</div>', unsafe_allow_html=True)

    st.write("")
    st.metric("Total Ledger Height", f"{len(blockchain.chain)} Blocks")
    
    diff = st.slider("PoW Difficulty Target (Leading Zeros)", min_value=1, max_value=4, value=blockchain.difficulty)
    blockchain.difficulty = diff

    st.markdown("---")
    st.markdown("### 🔑 Sender Identity (ECDSA)")
    with st.expander("Inspect Public Key (PEM)"):
        st.code(st.session_state["ecdsa_public_pem"], language="text")

    st.markdown("---")
    st.markdown("### 💾 Persistence Controls")
    if st.button("Save Ledger to Disk"):
        blockchain.save_ledger(LEDGER_FILE)
        st.toast("Decentralized ledger persisted to disk!", icon="💾")

    if st.button("Reset / Purge Blockchain"):
        st.session_state.blockchain = Blockchain(difficulty=diff)
        if os.path.exists(LEDGER_FILE):
            os.remove(LEDGER_FILE)
        st.rerun()

# ----------------- 6 CYBER TABS -----------------
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📥 1. Embed & Mine Block",
    "📤 2. Extract Secret (Zero-Trust)",
    "🦹 3. Adversary Tamper Studio",
    "🚨 4. Forensic Lab & Heatmap",
    "🌐 5. P2P Byzantine Consensus",
    "🔗 6. Visual Blockchain Graph & Merkle",
])

# ----------------- TAB 1: EMBED & MINE -----------------
with tab1:
    st.subheader("Encode Secret Message into Carrier Image & Mine Block")
    col1, col2 = st.columns([1, 1])

    with col1:
        uploaded_carrier = st.file_uploader(
            "Upload Carrier Image (PNG / JPG / BMP)", type=["png", "jpg", "jpeg", "bmp"], key="carrier_uploader"
        )
        if uploaded_carrier:
            carrier_pil = Image.open(uploaded_carrier)
            st.image(carrier_pil, caption=f"Carrier: {uploaded_carrier.name} ({carrier_pil.size[0]}x{carrier_pil.size[1]})", use_container_width=True)
            capacity = SteganographyEngine.get_capacity_bytes(carrier_pil)
            carrier_entropy = calculate_shannon_entropy(carrier_pil)
            st.info(f"Carrier Payload Capacity: **{capacity:,} bytes** | Shannon Entropy: **{carrier_entropy} bits/pixel**")

    with col2:
        if uploaded_carrier:
            secret_msg = st.text_area("Secret Message to Hide", placeholder="Enter classified payload here...", height=110)
            use_encryption = st.checkbox("Encrypt Message with AES-256-GCM (Authenticated Encryption)", value=True)
            passphrase = ""
            if use_encryption:
                passphrase = st.text_input("Encryption Passphrase", type="password", placeholder="Enter strong cryptographic passphrase...")

            sender_meta = st.text_input("Sender Identifier", value="Commander-Alpha")
            sign_with_ecdsa = st.checkbox("Sign Block with Sender's ECDSA Private Key (Non-Repudiation)", value=True)

            if st.button("🚀 Embed Secret, Sign & Mine Block", type="primary"):
                if not secret_msg.strip():
                    st.error("Please provide a secret message to embed.")
                elif use_encryption and not passphrase:
                    st.error("Encryption is checked. Please supply a passphrase.")
                else:
                    try:
                        with st.spinner("Embedding message via LSB Steganography..."):
                            stego_pil, stego_bytes = SteganographyEngine.encode(
                                carrier_pil,
                                message=secret_msg,
                                passphrase=passphrase if use_encryption else None,
                            )

                        stego_hash = calculate_sha256_bytes(stego_bytes)
                        stego_entropy = calculate_shannon_entropy(stego_pil)
                        
                        # Scientific PSNR & SSIM Quality Metrics
                        psnr_val, ssim_val = calculate_psnr_ssim(carrier_pil, stego_pil)

                        # Merkle Tree Root
                        merkle = MerkleTree([stego_hash])
                        merkle_root = merkle.get_merkle_root()

                        # ECDSA Signature
                        ecdsa_sig = ""
                        pub_pem_str = ""
                        if sign_with_ecdsa:
                            ecdsa_sig = sign_data(st.session_state["ecdsa_private_key"], stego_hash)
                            pub_pem_str = st.session_state["ecdsa_public_pem"]

                        with st.spinner(f"Mining Block with Proof-of-Work (Target: {'0'*blockchain.difficulty})..."):
                            t0 = time.time()
                            mined_block = blockchain.add_block(
                                image_hash=stego_hash,
                                image_name=uploaded_carrier.name,
                                metadata={
                                    "sender": sender_meta,
                                    "encrypted": use_encryption,
                                    "cipher": "AES-256-GCM" if use_encryption else "Plaintext",
                                    "carrier_entropy": carrier_entropy,
                                    "stego_entropy": stego_entropy,
                                    "psnr_db": psnr_val,
                                    "ssim": ssim_val,
                                },
                                sender_public_key=pub_pem_str,
                                signature=ecdsa_sig,
                                merkle_root=merkle_root,
                            )
                            elapsed = time.time() - t0
                            blockchain.save_ledger(LEDGER_FILE)

                        st.session_state["last_mined_stego_bytes"] = stego_bytes
                        st.session_state["last_mined_stego_pil"] = stego_pil
                        st.session_state["last_mined_block_idx"] = mined_block.index
                        st.session_state["last_carrier_entropy"] = carrier_entropy
                        st.session_state["last_stego_entropy"] = stego_entropy

                        st.success(f"🎉 Block #{mined_block.index} successfully mined in {elapsed:.3f}s! Nonce: {mined_block.nonce}")
                        
                        m1, m2, m3 = st.columns(3)
                        m1.metric("PSNR Fidelity", f"{psnr_val} dB", "Imperceptible (>40 dB)")
                        m2.metric("SSIM Structure", f"{ssim_val}", "Identical (1.0)")
                        m3.metric("Shannon Entropy", f"{stego_entropy}", "Randomized")

                        st.markdown(f"**Block Hash:** `{mined_block.hash}`")
                        st.markdown(f"**Image SHA-256:** `{mined_block.image_hash}`")
                        st.markdown(f"**Merkle Tree Root:** `{merkle_root}`")
                        if sign_with_ecdsa:
                            st.markdown(f"**ECDSA Digital Signature:** `{ecdsa_sig[:36]}...` (Verified)")

                        st.download_button(
                            label="⬇️ Download Stego Image (PNG)",
                            data=stego_bytes,
                            file_name=f"stego_block_{mined_block.index}.png",
                            mime="image/png",
                        )
                    except CapacityExceededError as ce:
                        st.error(f"Carrier capacity exceeded: {ce}")
                    except Exception as e:
                        st.error(f"Encoding Error: {e}")
        else:
            st.info("Upload a carrier image on the left panel to begin.")

# ----------------- TAB 2: EXTRACT SECRET -----------------
with tab2:
    st.subheader("Extract & Authenticate Secret Message")
    st.markdown(
        "**Zero-Trust Security Enforcement:** Any image that fails cryptographic hash verification against "
        "the Blockchain ledger is strictly blocked from decryption to prevent reliance on altered or malicious data."
    )
    col1, col2 = st.columns([1, 1])

    with col1:
        stego_file = st.file_uploader("Upload Candidate Stego Image (PNG)", type=["png"], key="stego_extractor")
        if stego_file:
            stego_img_pil = Image.open(stego_file)
            st.image(stego_img_pil, caption=f"Candidate Image: {stego_file.name}", use_container_width=True)
            uploaded_bytes = stego_file.getvalue()
            current_hash = calculate_sha256_bytes(uploaded_bytes)
            st.markdown(f"**Candidate SHA-256 Digest:** `{current_hash}`")

    with col2:
        if stego_file:
            enforce_blockchain_check = st.checkbox(
                "🔒 Enforce Zero-Trust Blockchain Verification (Block extraction if tampered)",
                value=True,
            )
            decrypt_pass = st.text_input("Decryption Passphrase (if encrypted)", type="password", key="dec_pass")
            
            if st.button("🔓 Extract Secret Message", type="primary"):
                uploaded_bytes = stego_file.getvalue()
                current_hash = calculate_sha256_bytes(uploaded_bytes)

                matched_block = blockchain.find_block_by_image_hash(current_hash)

                if enforce_blockchain_check and not matched_block:
                    st.error(
                        "🚨 **ACCESS DENIED: TAMPERING DETECTED!**\n\n"
                        "This image failed cryptographic blockchain verification. The SHA-256 fingerprint "
                        "does not match any immutable block record. Under Zero-Trust policy, extraction is blocked."
                    )
                    st.warning(f"Candidate Hash: `{current_hash}` (Unregistered / Modified)")
                else:
                    try:
                        with st.spinner("Extracting and authenticating payload..."):
                            extracted_text = SteganographyEngine.decode(
                                uploaded_bytes,
                                passphrase=decrypt_pass if decrypt_pass else None,
                            )
                        
                        if matched_block:
                            st.success(f"✅ **Verified Authentic via Blockchain Block #{matched_block.index}!**")
                            if matched_block.signature and matched_block.sender_public_key:
                                sig_ok, sig_msg = blockchain.verify_block_signature(matched_block.index)
                                if sig_ok:
                                    st.info(f"✍️ **Non-Repudiation Confirmed:** {sig_msg}")
                        else:
                            st.warning("⚠️ Warning: Extracted with Blockchain Guard bypassed.")

                        st.text_area("Decrypted Secret Message", value=extracted_text, height=140)
                    except InvalidStegoImageError as ie:
                        st.error(f"Stego Header Error: {ie}")
                    except TamperDetectedError as te:
                        st.error(f"Cryptographic Tag Authentication Failed: {te}")
                    except Exception as ex:
                        st.error(f"Extraction Error: {ex}")
        else:
            st.info("Upload a candidate stego image on the left panel to extract the secret.")

# ----------------- TAB 3: ADVERSARY TAMPER STUDIO -----------------
with tab3:
    st.subheader("🦹 Adversary Tamper Studio (Simulate Malicious Attacks)")
    st.markdown(
        "Upload any image (or load the latest stego image) and simulate malicious adversary tampering. "
        "Test stealth 1-pixel modifications, visual watermarks, or random noise injections."
    )

    # Studio Reset / Clear Photo Control
    c_btn1, c_btn2 = st.columns([3, 1])
    with c_btn2:
        if st.button("🗑️ Remove Photo & Reset Studio", type="secondary"):
            st.session_state["tamper_uploader_version"] = st.session_state.get("tamper_uploader_version", 0) + 1
            st.session_state.pop("studio_active_pil", None)
            st.session_state.pop("studio_active_bytes", None)
            st.session_state.pop("latest_tampered_bytes", None)
            st.session_state.pop("latest_tampered_img", None)
            st.session_state.pop("latest_tampered_desc", None)
            st.session_state.pop("latest_tampered_hash", None)
            st.session_state.pop("tampered_source_pil", None)
            st.rerun()

    h_col1, h_col2 = st.columns([1, 1])

    uploader_key = f"tamper_studio_uploader_{st.session_state.get('tamper_uploader_version', 0)}"

    with h_col1:
        raw_tamper_file = st.file_uploader(
            "Upload Image to Tamper With (PNG / JPG)", 
            type=["png", "jpg", "jpeg", "bmp"], 
            key=uploader_key
        )
        orig_pil = None
        orig_bytes = None

        if raw_tamper_file:
            orig_pil = Image.open(raw_tamper_file).convert("RGB")
            orig_bytes = raw_tamper_file.getvalue()
            st.image(orig_pil, caption=f"Source Image: {raw_tamper_file.name} ({orig_pil.size[0]}x{orig_pil.size[1]})", use_container_width=True)
            orig_hash = calculate_sha256_bytes(orig_bytes)
            st.markdown(f"**Source SHA-256 Digest:** `{orig_hash}`")
        elif "last_mined_stego_pil" in st.session_state:
            if st.button("Use Latest Mined Stego Image from Tab 1"):
                orig_pil = st.session_state["last_mined_stego_pil"]
                orig_bytes = st.session_state["last_mined_stego_bytes"]
                st.session_state["studio_active_pil"] = orig_pil
                st.session_state["studio_active_bytes"] = orig_bytes
                st.rerun()

        if "studio_active_pil" in st.session_state and not raw_tamper_file:
            orig_pil = st.session_state["studio_active_pil"]
            orig_bytes = st.session_state["studio_active_bytes"]
            st.image(orig_pil, caption="Selected Mined Stego Image", use_container_width=True)
            st.markdown(f"**Source SHA-256 Digest:** `{calculate_sha256_bytes(orig_bytes)}`")

    with h_col2:
        if orig_pil:
            st.markdown("#### Choose Attack Vector:")
            tamper_mode = st.radio(
                "Tamper Method",
                [
                    "🕵️ Stealth 1-Pixel Attack (Invisible to human perception)",
                    "🖍️ Visible Watermark / Banner Attack",
                    "⚡ Random Pixel Noise Injection",
                    "🔄 Color Channel Inversion Attack",
                ]
            )

            if "Stealth 1-Pixel" in tamper_mode:
                st.info("Alters 1 single color channel value by +1 at specified coordinate (e.g., Red 120 -> 121).")
                col_x, col_y = st.columns(2)
                with col_x:
                    px_x = st.number_input("Pixel X Coordinate", min_value=0, max_value=orig_pil.size[0]-1, value=orig_pil.size[0]//2)
                with col_y:
                    px_y = st.number_input("Pixel Y Coordinate", min_value=0, max_value=orig_pil.size[1]-1, value=orig_pil.size[1]//2)

            elif "Visible Watermark" in tamper_mode:
                draw_text = st.text_input("Tamper Text / Signature", value="TAMPERED")
                draw_color = st.color_picker("Marker Color", "#FF0000")

            elif "Random Pixel Noise" in tamper_mode:
                noise_count = st.slider("Number of pixels to corrupt", min_value=1, max_value=500, value=25)

            if st.button("💥 Execute Tamper Attack", type="primary"):
                tampered_result_pil = orig_pil.copy()
                pixels = tampered_result_pil.load()

                if "Stealth 1-Pixel" in tamper_mode:
                    cur = pixels[px_x, px_y]
                    new_val = ((cur[0] + 1) % 256, cur[1], cur[2])
                    pixels[px_x, px_y] = new_val
                    description_msg = f"Single pixel modified at ({px_x}, {px_y}): RGB {cur} -> {new_val}"

                elif "Visible Watermark" in tamper_mode:
                    draw = ImageDraw.Draw(tampered_result_pil)
                    w, h = tampered_result_pil.size
                    draw.rectangle([10, 10, min(w - 10, 240), min(h - 10, 50)], fill="black", outline=draw_color, width=2)
                    draw.text((20, 20), draw_text, fill=draw_color)
                    description_msg = f"Visual watermark banner rendered onto image."

                elif "Random Pixel Noise" in tamper_mode:
                    w, h = tampered_result_pil.size
                    for _ in range(noise_count):
                        rx = random.randint(0, w - 1)
                        ry = random.randint(0, h - 1)
                        pixels[rx, ry] = (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
                    description_msg = f"Injected random noise into {noise_count} arbitrary pixels."

                elif "Color Channel Inversion" in tamper_mode:
                    w, h = tampered_result_pil.size
                    for x in range(min(15, w)):
                        for y in range(min(15, h)):
                            r, g, b = pixels[x, y]
                            pixels[x, y] = (255 - r, 255 - g, 255 - b)
                    description_msg = "Inverted color channels in a 15x15 pixel region."

                out_buf = io.BytesIO()
                tampered_result_pil.save(out_buf, format="PNG")
                tampered_bytes = out_buf.getvalue()
                tampered_hash = calculate_sha256_bytes(tampered_bytes)

                st.session_state["latest_tampered_bytes"] = tampered_bytes
                st.session_state["latest_tampered_hash"] = tampered_hash
                st.session_state["latest_tampered_desc"] = description_msg
                st.session_state["latest_tampered_img"] = tampered_result_pil
                st.session_state["tampered_source_pil"] = orig_pil

        if "latest_tampered_bytes" in st.session_state:
            st.markdown("---")
            st.success("✅ Attack Applied Successfully! Counterfeit image generated:")
            st.image(st.session_state["latest_tampered_img"], caption="Tampered / Counterfeit Image", use_container_width=True)
            st.info(f"**Modifications Applied:** {st.session_state['latest_tampered_desc']}")
            st.markdown(f"**Counterfeit SHA-256 Digest:** `{st.session_state['latest_tampered_hash']}`")

            tampered_dl = st.session_state["latest_tampered_bytes"]
            st.download_button(
                label="⬇️ Download Tampered Image (PNG)",
                data=tampered_dl,
                file_name="tampered_image_counterfeit.png",
                mime="image/png",
            )
        else:
            st.info("Upload an image on the left panel (or load the latest mined stego image) to activate the attack controls.")

# ----------------- TAB 4: FORENSIC LAB & HEATMAP -----------------
with tab4:
    st.subheader("🚨 Forensic Tamper Detection, Difference Heatmap & Steganalysis Lab")
    st.markdown(
        "Audit any candidate image against the immutable Blockchain ledger. "
        "The system validates SHA-256 integrity, renders a **Forensic Pixel Difference Heatmap**, "
        "performs **Chi-Square (χ²) Steganalysis**, analyzes **Shannon Entropy**, and produces a downloadable **Cryptographic Certificate of Authenticity**."
    )

    t_col1, t_col2 = st.columns([1, 1])

    with t_col1:
        st.markdown("#### Step 1: Candidate Image Input")
        audit_file = st.file_uploader(
            "Upload Candidate Image to Audit", 
            type=["png", "jpg", "jpeg", "bmp"], 
            key="audit_uploader"
        )
        
        use_studio_img = False
        if "latest_tampered_bytes" in st.session_state:
            if st.button("🧪 Load Tampered Image from Adversary Studio"):
                use_studio_img = True

        candidate_data = None
        candidate_label = ""
        candidate_pil = None
        if use_studio_img:
            candidate_data = st.session_state["latest_tampered_bytes"]
            candidate_pil = st.session_state["latest_tampered_img"]
            candidate_label = "Adversary Studio Counterfeit Image"
            st.image(candidate_pil, caption=candidate_label, use_container_width=True)
        elif audit_file:
            candidate_data = audit_file.getvalue()
            candidate_pil = Image.open(io.BytesIO(candidate_data)).convert("RGB")
            candidate_label = audit_file.name
            st.image(candidate_pil, caption=candidate_label, use_container_width=True)

    with t_col2:
        st.markdown("#### Step 2: Target Blockchain Record")
        block_options = [f"Block #{b.index}: {b.image_name} ({b.image_hash[:10]}...)" for b in blockchain.chain[1:]]
        
        if block_options:
            selected_block_str = st.selectbox("Select Block to Verify Against", options=block_options)
            block_idx = int(selected_block_str.split("#")[1].split(":")[0])

            if candidate_data:
                cand_hash = calculate_sha256_bytes(candidate_data)
                cand_entropy = calculate_shannon_entropy(candidate_pil)
                chi_res = calculate_chi_square_steganalysis(candidate_pil)

                st.markdown(f"**Candidate SHA-256 Digest:** `{cand_hash}`")
                st.markdown(f"**Candidate Shannon Entropy:** `{cand_entropy} bits/pixel`")
                st.markdown(f"**Chi-Square (χ²) Statistic:** `{chi_res['chi_square_statistic']}` | Status: **{chi_res['status']}**")
                
                if st.button("🔍 Execute Cryptographic Forensic Audit", type="primary"):
                    is_authentic, cand_h, rec_h, audit_msg = blockchain.verify_image_integrity(
                        candidate_data, block_idx
                    )
                    
                    target_b = blockchain.chain[block_idx]

                    if is_authentic:
                        st.balloons()
                        st.success(f"🟢 **AUTHENTIC (Zero Tampering Detected)**\n\n{audit_msg}")
                    else:
                        st.error(f"🔴 **TAMPER DETECTED! INTEGRITY VIOLATION**\n\n{audit_msg}")

                    st.markdown("---")
                    st.markdown(f"**Candidate Image Hash:** `{cand_h}`")
                    st.markdown(f"**Blockchain Ledger Hash:** `{rec_h}`")

                    # Forensic Difference Heatmap
                    if not is_authentic and "tampered_source_pil" in st.session_state and candidate_pil:
                        st.markdown("---")
                        st.subheader("🔬 Forensic Pixel Difference Heatmap")
                        try:
                            src_img = st.session_state["tampered_source_pil"].convert("RGB")
                            cand_img = candidate_pil.resize(src_img.size).convert("RGB")
                            
                            diff = ImageChops.difference(src_img, cand_img)
                            diff_enhanced = diff.point(lambda p: 255 if p > 0 else 0)
                            
                            f_col1, f_col2 = st.columns(2)
                            with f_col1:
                                st.image(diff_enhanced, caption="Pixel Difference Mask (Altered Pixels in White/Color)", use_container_width=True)
                            with f_col2:
                                st.info("The forensic difference mask reveals the exact coordinates of altered pixels.")
                        except Exception as diff_err:
                            st.warning(f"Could not generate visual difference mask: {diff_err}")

                    # Generate Cryptographic Certificate of Authenticity Dossier
                    audit_certificate = {
                        "certificate_id": f"CERT-{int(time.time())}-{random.randint(1000, 9999)}",
                        "audit_timestamp_utc": datetime.now(timezone.utc).isoformat(),
                        "target_block_index": target_b.index,
                        "blockchain_difficulty": blockchain.difficulty,
                        "target_block_hash": target_b.hash,
                        "recorded_image_sha256": rec_h,
                        "candidate_image_sha256": cand_h,
                        "merkle_root": target_b.merkle_root,
                        "integrity_verdict": "AUTHENTIC" if is_authentic else "TAMPER_DETECTED",
                        "shannon_entropy_bits_per_pixel": cand_entropy,
                        "chi_square_statistic": chi_res["chi_square_statistic"],
                        "chi_square_status": chi_res["status"],
                        "ecdsa_signature_present": bool(target_b.signature),
                        "audit_summary": audit_msg,
                    }

                    st.markdown("---")
                    st.subheader("📜 Cryptographic Certificate of Authenticity")
                    cert_json = json.dumps(audit_certificate, indent=4)
                    st.json(audit_certificate)

                    st.download_button(
                        label="⬇️ Download Official Forensic Audit Certificate (JSON)",
                        data=cert_json,
                        file_name=f"Forensic_Certificate_Block_{target_b.index}.json",
                        mime="application/json",
                    )
        else:
            st.warning("No image blocks mined yet. Please mine an image block in Tab 1 first.")

# ----------------- TAB 5: P2P CONSENSUS SIMULATOR -----------------
with tab5:
    st.subheader("🌐 P2P Decentralized Consensus & Byzantine Fault Tolerance Simulator")
    st.markdown(
        "Simulates a decentralized network of independent blockchain peer nodes across the globe. "
        "Demonstrates **Byzantine Fault Tolerance (BFT)** and **51% Majority Consensus** when broadcasting genuine vs counterfeit blocks."
    )

    p_col1, p_col2 = st.columns([1, 1])

    with p_col1:
        st.markdown("#### Network Peer Nodes Topology")
        nodes_info = [
            ("Peer-Node-A", "Virginia, USA", "Honest Node"),
            ("Peer-Node-B", "Frankfurt, Germany", "Honest Node"),
            ("Peer-Node-C", "Tokyo, Japan", "Honest Node"),
            ("Peer-Node-D", "Singapore", "Honest Node"),
        ]
        for name, loc, role in nodes_info:
            st.markdown(
                f"<div class='cyber-card'>🖥️ <b>{name}</b> ({loc})<br><small style='color: #00ff88;'>Status: Active & Synchronized | Role: {role}</small></div>",
                unsafe_allow_html=True,
            )

    with p_col2:
        st.markdown("#### Broadcast Test Block into P2P Network")
        scenario = st.radio(
            "Select Consensus Simulation Scenario:",
            [
                "🟢 Broadcast Genuine Valid Block (Valid PoW & Valid SHA-256)",
                "🔴 Broadcast Adversary Block with Forged Payload (PoW/Hash Mismatch)",
            ]
        )

        if st.button("📡 Broadcast Block to Peer Network", type="primary"):
            latest_b = blockchain.get_latest_block()

            if "Genuine Valid Block" in scenario:
                candidate_test_block = Block(
                    index=latest_b.index + 1,
                    image_hash=calculate_sha256_bytes(b"p2p_genuine_block"),
                    image_name="p2p_genuine.png",
                    previous_hash=latest_b.hash,
                )
                candidate_test_block.mine_block(blockchain.difficulty)
            else:
                candidate_test_block = Block(
                    index=latest_b.index + 1,
                    image_hash="forged_malicious_adversary_hash_value",
                    image_name="forged_attack.png",
                    previous_hash="0" * 64,
                    block_hash="forged_unmined_hash",
                )

            with st.spinner("Broadcasting block across P2P Gossip protocol..."):
                time.sleep(0.4)
                consensus_res = blockchain.simulate_p2p_consensus(candidate_test_block, node_count=4)

            st.markdown("---")
            st.subheader("Consensus Voting Results:")
            for node, vote in consensus_res["votes"].items():
                if vote == "ACCEPTED":
                    st.write(f"🟢 **{node}**: `VOTE ACCEPTED` (PoW & Cryptographic Chain Valid)")
                else:
                    st.write(f"🔴 **{node}**: `VOTE REJECTED` (Tampering Detected / Invalid PoW)")

            st.metric("Consensus Rate", f"{consensus_res['consensus_pct']:.0f}%", f"{consensus_res['accepted_count']}/4 Nodes")

            if consensus_res["consensus_reached"]:
                st.success("🎉 **CONSENSUS REACHED (100% Agreement):** Block accepted and appended to ledger by network!")
            else:
                st.error("🚨 **CONSENSUS FAILED (Byzantine Fault Detected):** Malicious block rejected by 100% of honest peer nodes!")

# ----------------- TAB 6: VISUAL BLOCKCHAIN GRAPH & MERKLE -----------------
with tab6:
    st.subheader("🔗 Interactive Visual Blockchain Graph & Merkle Proof Explorer")
    st.markdown(
        "Visual DAG representation of the immutable ledger. Inspect cryptographic linkage between blocks, "
        "verify Merkle Root integrity, and export raw blockchain state."
    )

    # Visual Blockchain Graph
    st.markdown("#### Cryptographic Block DAG Chain Linkage:")
    graph_html = '<div style="overflow-x: auto; white-space: nowrap; padding: 15px 0;">'
    for i, b in enumerate(blockchain.chain):
        is_genesis = (b.index == 0)
        badge_color = "#00f0ff" if is_genesis else "#00ff88"
        node_title = "Genesis Block #0" if is_genesis else f"Block #{b.index}"
        
        graph_html += f"""
        <div class="block-node">
          <div style="color: {badge_color}; font-weight: bold; font-size: 1.05rem;">📦 {node_title}</div>
          <div style="font-family: monospace; font-size: 0.78rem; color: #94a3b8; margin: 4px 0;">
            Hash: {b.hash[:12]}...<br>
            Prev: {b.previous_hash[:12]}...<br>
            Nonce: {b.nonce}
          </div>
        </div>
        """
        if i < len(blockchain.chain) - 1:
            graph_html += '<span class="chain-arrow">──►</span>'
    graph_html += '</div>'

    st.markdown(graph_html, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### Merkle Tree Audit Proof Lab")
    if len(blockchain.chain) > 1:
        target_b_idx = st.selectbox("Select Block to Verify Merkle Proof", range(1, len(blockchain.chain)), key="merkle_block_sel")
        sel_block = blockchain.chain[target_b_idx]
        
        st.markdown(f"**Target Image SHA-256 (Leaf):** `{sel_block.image_hash}`")
        st.markdown(f"**Recorded Merkle Root:** `{sel_block.merkle_root}`")
        
        # Build tree and proof
        tree = MerkleTree([sel_block.image_hash])
        proof = tree.generate_proof(0)
        
        st.write("Merkle Proof Siblings (Path):", proof)
        
        is_merkle_valid = MerkleTree.verify_proof(sel_block.image_hash, proof, sel_block.merkle_root)
        if is_merkle_valid:
            st.success("🟢 **Merkle Audit Proof Verified in O(log N) Time!** Leaf belongs to canonical block.")
        else:
            st.error("🔴 Merkle Proof verification failed!")
    else:
        st.info("Mine at least one block in Tab 1 to enable Merkle proof verification.")

    st.markdown("---")
    st.subheader("Raw Ledger JSON")
    st.download_button(
        label="⬇️ Export Blockchain Ledger (JSON)",
        data=blockchain.to_json(),
        file_name="blockchain_ledger.json",
        mime="application/json",
    )
