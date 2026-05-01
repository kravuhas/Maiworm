```html
<p align="center">
<svg width="500" height="120" viewBox="0 0 500 120" xmlns="http://www.w3.org/2000/svg">

<style>
.text {
  font-family: monospace;
  font-size: 60px;
  fill: #ff0033;
  text-anchor: middle;
  dominant-baseline: middle;
  filter: url(#glow);
  animation: glitch 1s infinite;
}

@keyframes glitch {
  0% { transform: translate(0,0); }
  20% { transform: translate(-2px,2px); }
  40% { transform: translate(2px,-2px); }
  60% { transform: translate(-1px,1px); }
  80% { transform: translate(1px,-1px); }
  100% { transform: translate(0,0); }
}
</style>

<defs>
  <filter id="glow">
    <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
    <feMerge>
      <feMergeNode in="coloredBlur"/>
      <feMergeNode in="SourceGraphic"/>
    </feMerge>
  </filter>
</defs>

<rect width="100%" height="100%" fill="black"/>

<text x="50%" y="50%" class="text">
  MAIgpt
</text>

</svg>
</p>
```                                                                                  
> 🔴 Advanced AI-powered security platform with cinematic hacker interface.

---

## 🚀 Features

* 🔍 Web & Code Security Scanner
* 🤖 AI-assisted vulnerability analysis
* ⚡ Real-time scan updates (WebSocket)
* 🧊 3D interactive interface (Three.js)
* 📊 Vulnerability dashboard (Chart.js)
* 🖥️ CLI + Web Interface

---

## 🎬 Hacker Interface Preview

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/7cf6d285-e8c5-477f-b7fc-1bfc6f2ac34c" />

---

## 🧠 Tech Stack

* Python (Backend)
* Flask / FastAPI
* WebSockets
* Three.js
* Chart.js
* Rich + Typer

---

## ⚙️ Usage

```bash
pip install -r requirements.txt
```

```bash
python main.py
```

```
http://localhost:8000
```

---

## 🔍 CLI Example

```bash
python main.py scan https://example.com --ai
```

---

## 📊 Output

* 🔴 Critical → 🟢 Info classification
* OWASP mapping
* CWE references
* Risk scoring

---

## ⚠️ Disclaimer

This tool is for **educational and authorized testing only**.

---

## 🧠 Author

Felipe — Security Researcher / Bug Bounty Hunter

---

## 💀 MAI CORE STATUS

```
[ SYSTEM ONLINE ]
[ AI CONNECTED ]
[ SCANNER ACTIVE ]
[ READY FOR TARGET ]
```
