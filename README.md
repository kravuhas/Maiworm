<!DOCTYPE html>
<html lang="pt">
<head>
<meta charset="UTF-8">
<title>MAI // Security Interface</title>
<link rel="stylesheet" href="/static/style.css">
<script src="https://cdn.jsdelivr.net/npm/three@0.152.2/build/three.min.js"></script>
</head>

<body>

<canvas id="bg"></canvas>

<div class="overlay">

    <h1>🧠 MAI TERMINAL</h1>

    <div class="panel">
        <input id="target" placeholder="https://target.com">
        <button onclick="startScan()">SCAN</button>
    </div>

    <pre id="log"></pre>

    <div class="chart">
        <canvas id="chart"></canvas>
    </div>

</div>
<style>
body {
    margin: 0;
    background: black;
    font-family: monospace;
    color: #00ff88;
}

#bg {
    position: fixed;
    top: 0;
    left: 0;
    z-index: 0;
}

.overlay {
    position: relative;
    z-index: 2;
    padding: 20px;
}

h1 {
    text-align: center;
    text-shadow: 0 0 10px #00ff88;
}

.panel {
    text-align: center;
    margin-bottom: 20px;
}

input {
    padding: 10px;
    width: 300px;
    background: black;
    border: 1px solid #00ff88;
    color: #00ff88;
}

button {
    padding: 10px;
    background: #00ff88;
    border: none;
    cursor: pointer;
}

pre {
    background: rgba(0,0,0,0.7);
    padding: 10px;
    height: 200px;
    overflow-y: auto;
}

.chart {
    margin-top: 20px;
}
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<script>
const log = document.getElementById("log");

function addLog(msg) {
    log.textContent += msg + "\\n";
}

// =====================
// WEBSOCKET (REALTIME)
// =====================
let socket = new WebSocket("ws://localhost:8000/ws");

socket.onmessage = (event) => {
    addLog(event.data);
};

// =====================
// SCAN
// =====================
function startScan() {
    let target = document.getElementById("target").value;
    fetch("/scan/" + target);
}

// =====================
// 3D BLOB (MAIWORM)
// =====================
let scene = new THREE.Scene();
let camera = new THREE.PerspectiveCamera(75, innerWidth/innerHeight, 0.1, 1000);

let renderer = new THREE.WebGLRenderer({canvas: document.getElementById("bg")});
renderer.setSize(innerWidth, innerHeight);

let geometry = new THREE.IcosahedronGeometry(1, 32);

let material = new THREE.MeshStandardMaterial({
    color: 0x00ff88,
    metalness: 1,
    roughness: 0.2
});

let mesh = new THREE.Mesh(geometry, material);
scene.add(mesh);

let light = new THREE.PointLight(0x00ff88, 2);
light.position.set(5,5,5);
scene.add(light);

camera.position.z = 3;

let clock = new THREE.Clock();

function animate() {
    requestAnimationFrame(animate);

    let t = clock.getElapsedTime();

    mesh.rotation.x += 0.003;
    mesh.rotation.y += 0.005;

    mesh.scale.x = 1 + Math.sin(t)*0.1;
    mesh.scale.y = 1 + Math.cos(t)*0.1;

    renderer.render(scene, camera);
}

animate();

// =====================
// CHART
// =====================
let ctx = document.getElementById("chart");

new Chart(ctx, {
    type: "bar",
    data: {
        labels: ["Critical", "High", "Medium", "Low"],
        datasets: [{
            label: "Vulnerabilidades",
            data: [0,0,0,0]
        }]
    }
});
</script>

</body>
</html>
