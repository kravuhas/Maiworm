# 🧠 MAI — Intelligent Security Scanner

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

```html
<!DOCTYPE html>
<html lang="pt">
<head>
<meta charset="UTF-8">
<title>MAI // RED MODE</title>

<style>
body {
    margin: 0;
    background: black;
    font-family: monospace;
    color: #ff0033;
    overflow: hidden;
}

/* GLITCH EFFECT */
h1 {
    text-align: center;
    color: #ff0033;
    text-shadow: 
        0 0 5px #ff0033,
        0 0 20px #ff0033,
        0 0 40px #ff0000;
    animation: glitch 1s infinite;
}

@keyframes glitch {
    0% { transform: translate(0); }
    20% { transform: translate(-2px, 2px); }
    40% { transform: translate(2px, -2px); }
    60% { transform: translate(-1px, 1px); }
    80% { transform: translate(1px, -1px); }
    100% { transform: translate(0); }
}

/* TERMINAL */
.panel {
    text-align: center;
    margin-top: 20px;
}

input {
    padding: 10px;
    width: 300px;
    background: black;
    border: 1px solid #ff0033;
    color: #ff0033;
}

button {
    padding: 10px;
    background: #ff0033;
    border: none;
    cursor: pointer;
    color: black;
    font-weight: bold;
}

pre {
    background: rgba(0,0,0,0.8);
    padding: 10px;
    height: 200px;
    overflow-y: auto;
    border: 1px solid #ff0033;
}

/* MATRIX EFFECT */
canvas {
    position: fixed;
    top: 0;
    left: 0;
    z-index: -1;
}
</style>
</head>

<body>

<canvas id="matrix"></canvas>

<h1>MAI TERMINAL</h1>

<div class="panel">
    <input placeholder="https://target.com">
    <button>SCAN</button>
</div>

<pre>
[+] Initializing MAI...
[+] Loading modules...
[+] AI Engine Ready
[+] Waiting target...
</pre>

<script>
// MATRIX RAIN EFFECT
let canvas = document.getElementById("matrix");
let ctx = canvas.getContext("2d");

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

let letters = "01";
let fontSize = 14;
let columns = canvas.width / fontSize;

let drops = [];
for (let i = 0; i < columns; i++) drops[i] = 1;

function draw() {
    ctx.fillStyle = "rgba(0,0,0,0.05)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = "#ff0033";
    ctx.font = fontSize + "px monospace";

    for (let i = 0; i < drops.length; i++) {
        let text = letters[Math.floor(Math.random()*letters.length)];
        ctx.fillText(text, i*fontSize, drops[i]*fontSize);

        if (drops[i]*fontSize > canvas.height && Math.random() > 0.975)
            drops[i] = 0;

        drops[i]++;
    }
}

setInterval(draw, 33);
</script>

</body>
</html>
```

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
