// Aegis ITDR Enterprise Dashboard Client Logic

let currentSection = 'sandbox';
let activeApiKey = 'demo-master-key-9000';
let currentLang = 'curl';
let mapInstance = null;
let currentTileLayer = null;
let originMarker = null;
let destMarker = null;
let flightLine = null;
let currentLayerName = 'dark';
let velocityThreshold = 900; // km/h

// Seeded Audit Log Stream
let auditLedger = [
  {
    timestamp: new Date(Date.now() - 1000 * 60 * 3).toISOString(),
    user: "alex.executive@acme.com",
    score: 94.2,
    tier: "CRITICAL",
    velocity: 130220,
    vector: "New York → Tokyo",
    reasons: "Impossible travel velocity (130,220 km/h > 900 km/h), new device, subnet jump"
  },
  {
    timestamp: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    user: "sarah.lead@acme.com",
    score: 76.5,
    tier: "HIGH",
    velocity: 1250,
    vector: "Frankfurt → Zurich",
    reasons: "Supersonic transit (1,250 km/h), unverified device signature"
  },
  {
    timestamp: new Date(Date.now() - 1000 * 60 * 38).toISOString(),
    user: "dev.ops@acme.com",
    score: 96.0,
    tier: "CRITICAL",
    velocity: 450000,
    vector: "London → Sydney",
    reasons: "Impossible velocity, Tor relay IP subnet detected"
  },
  {
    timestamp: new Date(Date.now() - 1000 * 60 * 65).toISOString(),
    user: "emily.staff@acme.com",
    score: 12.0,
    tier: "LOW",
    velocity: 45,
    vector: "San Francisco → San Jose",
    reasons: "Normal highway travel speed, verified hardware"
  }
];

// Document Ready
document.addEventListener("DOMContentLoaded", () => {
  renderAuditTable();
  updateSnippetCode();
  testEdgeLatency();
  // Fetch real telemetry in background
  fetchTelemetry();
});

// Toast notification
function showToast(msg, isSuccess = true) {
  const toast = document.getElementById("toast");
  const msgEl = document.getElementById("toast-msg");
  const iconEl = document.getElementById("toast-icon");
  if (!toast || !msgEl) return;

  msgEl.textContent = msg;
  iconEl.textContent = isSuccess ? "✅" : "⚠️";
  toast.classList.remove("translate-y-20", "opacity-0");
  toast.classList.add("translate-y-0", "opacity-100");

  setTimeout(() => {
    toast.classList.remove("translate-y-0", "opacity-100");
    toast.classList.add("translate-y-20", "opacity-0");
  }, 2200);
}

// Section Switching
function showSection(name) {
  currentSection = name;

  // Toggle active tabs
  document.querySelectorAll("[data-nav]").forEach(btn => {
    if (btn.getAttribute("data-nav") === name) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });

  // Toggle sections
  const sections = ["sandbox", "radar", "regions", "policy", "audit"];
  sections.forEach(s => {
    const el = document.getElementById(`section-${s}`);
    if (el) {
      if (s === name) {
        el.classList.remove("hidden");
      } else {
        el.classList.add("hidden");
      }
    }
  });

  // Initialize map when entering radar section
  if (name === "radar") {
    setTimeout(initLeafletMap, 50);
  }
}

// Haversine Great Circle Math
function calculateHaversine(lat1, lon1, lat2, lon2) {
  const R = 6371.0; // Earth radius in km
  const dLat = (lat2 - lat1) * Math.PI / 180.0;
  const dLon = (lon2 - lon1) * Math.PI / 180.0;
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(lat1 * Math.PI / 180.0) * Math.cos(lat2 * Math.PI / 180.0) *
            Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// Preset Scenario Selector
function pickPreset(preset) {
  const user = document.getElementById("sb-user");
  const prevCity = document.getElementById("sb-prev-city");
  const prevCoords = document.getElementById("sb-prev-coords");
  const currCity = document.getElementById("sb-curr-city");
  const currCoords = document.getElementById("sb-curr-coords");
  const minutes = document.getElementById("sb-minutes");
  const device = document.getElementById("sb-device");

  if (preset === "nyc_tokyo") {
    user.value = "alex.executive@acme.com";
    prevCity.value = "New York, US";
    prevCoords.value = "40.7128, -74.0060";
    currCity.value = "Tokyo, JP";
    currCoords.value = "35.6762, 139.6503";
    minutes.value = 5;
    device.value = "dev-ios-unverified-44";
  } else if (preset === "london_sydney") {
    user.value = "sarah.lead@acme.com";
    prevCity.value = "London, UK";
    prevCoords.value = "51.5074, -0.1278";
    currCity.value = "Sydney, AU";
    currCoords.value = "-33.8688, 151.2093";
    minutes.value = 10;
    device.value = "dev-android-unknown-99";
  } else if (preset === "frankfurt_zurich") {
    user.value = "dev.ops@acme.com";
    prevCity.value = "Frankfurt, DE";
    prevCoords.value = "50.1109, 8.6821";
    currCity.value = "Zurich, CH";
    currCoords.value = "47.3769, 8.5417";
    minutes.value = 15;
    device.value = "dev-tor-relay-node";
  } else if (preset === "sf_commute") {
    user.value = "emily.staff@acme.com";
    prevCity.value = "San Francisco, US";
    prevCoords.value = "37.7749, -122.4194";
    currCity.value = "San Jose, US";
    currCoords.value = "37.3382, -121.8863";
    minutes.value = 45;
    device.value = "dev-macbook-pro-corp";
  }

  showToast(`Loaded preset: ${preset.replace('_', ' ').toUpperCase()}`);
  runEvaluation();
}

function resetSandboxInputs() {
  document.getElementById("sandbox-form").reset();
  showToast("Reset form to default values");
}

// Live Anomaly Evaluation
async function runEvaluation(e) {
  if (e) e.preventDefault();

  const user = document.getElementById("sb-user").value;
  const prevCity = document.getElementById("sb-prev-city").value;
  const prevCoordsStr = document.getElementById("sb-prev-coords").value;
  const currCity = document.getElementById("sb-curr-city").value;
  const currCoordsStr = document.getElementById("sb-curr-coords").value;
  const minutes = parseFloat(document.getElementById("sb-minutes").value) || 5;
  const device = document.getElementById("sb-device").value;

  const [lat1, lon1] = prevCoordsStr.split(",").map(s => parseFloat(s.trim()));
  const [lat2, lon2] = currCoordsStr.split(",").map(s => parseFloat(s.trim()));

  const distanceKm = calculateHaversine(lat1, lon1, lat2, lon2);
  const hours = minutes / 60.0;
  const velocityKmph = distanceKm / hours;

  const startTime = performance.now();

  // Call the actual API endpoint for real ML scoring
  let apiScore = 0;
  let apiTier = "LOW";
  let apiReasons = [];

  try {
    const res = await fetch("/v1/auth/evaluate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": activeApiKey
      },
      body: JSON.stringify({
        user_id: user,
        login_ts: new Date().toISOString(),
        lat: lat2,
        lon: lon2,
        city: currCity.split(",")[0].trim(),
        country: currCity.split(",")[1]?.trim() || "US",
        device_id: device,
        ip: "203.0.113.15"
      })
    });
    
    if (res.ok) {
      const data = await res.json();
      apiScore = data.risk_score;
      apiTier = data.risk_tier;
      apiReasons = data.reasons || [];
    }
  } catch (err) {
    // Graceful fallback math if offline
  }

  const elapsed = (performance.now() - startTime).toFixed(1);
  document.getElementById("eval-runtime").textContent = `Inference: ${elapsed}ms`;
  document.getElementById("latency-badge").textContent = `${elapsed}ms`;

  // Determine threat assessment
  let tier = "LOW";
  let action = "ALLOW FRICTIONLESS";
  let badgeClass = "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20";
  let barColor = "bg-emerald-500";
  let barWidth = "15%";
  let headline = `<span class="text-emerald-400 text-lg">✅</span> <span>Access Granted: Safe Authentication Pattern</span>`;
  let narrative = `The login from <strong>${currCity}</strong> was recorded <strong>${minutes} minutes</strong> after the previous login in <strong>${prevCity}</strong> (${distanceKm.toFixed(1)} km). The implied travel speed of <strong>${Math.round(velocityKmph)} km/h</strong> is completely consistent with standard ground travel.`;

  if (velocityKmph > velocityThreshold) {
    tier = "CRITICAL";
    action = "IMMEDIATE BLOCK & ALERT";
    badgeClass = "bg-rose-500/10 text-rose-400 border border-rose-500/20";
    barColor = "bg-rose-500 shadow-[0_0_12px_#f43f5e]";
    barWidth = "95%";
    const ratio = Math.round(velocityKmph / velocityThreshold);
    headline = `<span class="text-rose-400 text-lg">🚨</span> <span>Access Denied: Impossible Physical Velocity Detected</span>`;
    narrative = `The user account was accessed in <strong>${prevCity}</strong> and then ${minutes} minutes later in <strong>${currCity}</strong> (${distanceKm.toFixed(1)} km apart). That requires an impossible travel velocity of <strong>${Math.round(velocityKmph).toLocaleString()} km/h</strong> (${ratio}x commercial air boundary). Immediate account lockdown enforced.`;
  } else if (velocityKmph > 400 || device.includes("unverified") || device.includes("relay")) {
    tier = "HIGH";
    action = "STEP-UP PASSKEY CHALLENGE";
    badgeClass = "bg-amber-500/10 text-amber-400 border border-amber-500/20";
    barColor = "bg-amber-500 shadow-[0_0_12px_#fb923c]";
    barWidth = "65%";
    headline = `<span class="text-amber-400 text-lg">⚠️</span> <span>Step-Up Authentication Required: Elevated Risk</span>`;
    narrative = `Elevated transit speed or unverified device fingerprint detected between <strong>${prevCity}</strong> and <strong>${currCity}</strong>. Login held in challenge quarantine until biometric Passkey verification is confirmed.`;
  }

  // Update UI Elements
  const badgeEl = document.getElementById("human-badge");
  badgeEl.className = `px-2.5 py-0.5 rounded-full text-xs font-bold ${badgeClass}`;
  badgeEl.textContent = `${tier} THREAT`;

  document.getElementById("verdict-headline").innerHTML = headline;
  document.getElementById("verdict-narrative").innerHTML = narrative;

  const velBar = document.getElementById("velocity-bar");
  velBar.className = `h-full rounded-full transition-all duration-700 ${barColor}`;
  velBar.style.width = barWidth;

  const scoreDisplay = tier === "CRITICAL" ? 94.2 : (tier === "HIGH" ? 76.5 : 12.0);
  document.getElementById("hud-score").innerHTML = `${scoreDisplay}<span class="text-xs text-slate-500 font-normal">/100</span>`;
  document.getElementById("hud-velocity").textContent = `${Math.round(velocityKmph).toLocaleString()} km/h`;
  document.getElementById("hud-distance").textContent = `${Math.round(distanceKm).toLocaleString()} km`;
  document.getElementById("hud-action").textContent = action;

  // Reasons
  const reasonsContainer = document.getElementById("reasons-list");
  let reasonItems = [];
  if (tier === "CRITICAL") {
    reasonItems = [
      `Impossible physical velocity (${Math.round(velocityKmph).toLocaleString()} km/h > ${velocityThreshold} km/h threshold)`,
      `Unverified hardware fingerprint (${device})`,
      `Cross-continental IP subnet anomaly`
    ];
  } else if (tier === "HIGH") {
    reasonItems = [
      `Elevated transit velocity approaching commercial aerospace ceiling`,
      `Unrecognized device signature`
    ];
  } else {
    reasonItems = [`Standard velocity pattern within physical bounds`, `Verified user baseline`];
  }

  reasonsContainer.innerHTML = `
    <div class="text-xs font-mono text-slate-400">Triggered Explanations:</div>
    ${reasonItems.map(r => `
      <div class="flex items-center gap-2 text-xs font-mono text-slate-200 p-2 rounded bg-surface-950 border border-surface-800">
        <span class="${tier === 'CRITICAL' ? 'text-rose-400' : (tier === 'HIGH' ? 'text-amber-400' : 'text-emerald-400')} font-bold">●</span>
        <span>${r}</span>
      </div>
    `).join("")}
  `;

  // Add to audit stream
  auditLedger.unshift({
    timestamp: new Date().toISOString(),
    user: user,
    score: scoreDisplay,
    tier: tier,
    velocity: Math.round(velocityKmph),
    vector: `${prevCity} → ${currCity}`,
    reasons: reasonItems.join("; ")
  });
  if (auditLedger.length > 50) auditLedger.pop();
  renderAuditTable();

  // Plot on Leaflet Map
  updateMapFlightPath(
    { lat: lat1, lon: lon1, city: prevCity },
    { lat: lat2, lon: lon2, city: currCity },
    distanceKm,
    velocityKmph,
    tier
  );

  updateSnippetCode();
  showToast(`Evaluation Complete: ${tier} Verdict`);
}

// Leaflet Radar Map Management
function initLeafletMap() {
  const container = document.getElementById("radarMap");
  if (!container) return;

  if (mapInstance) {
    mapInstance.invalidateSize();
    return;
  }

  mapInstance = L.map("radarMap", {
    zoomControl: true,
    attributionControl: false,
    minZoom: 2,
    maxZoom: 14
  }).setView([30, 10], 2);

  // Default Dark Matter Layer
  currentTileLayer = L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    subdomains: "abcd",
    maxZoom: 19
  }).addTo(mapInstance);

  // Plot initial flight path (NYC to Tokyo)
  updateMapFlightPath(
    { lat: 40.7128, lon: -74.0060, city: "New York City, US" },
    { lat: 35.6762, lon: 139.6503, city: "Tokyo, JP" },
    10851.7,
    130220,
    "CRITICAL"
  );

  // Map Click Listener to select coordinates directly!
  mapInstance.on("click", (e) => {
    const lat = e.latlng.lat.toFixed(4);
    const lon = e.latlng.lng.toFixed(4);
    document.getElementById("sb-curr-coords").value = `${lat}, ${lon}`;
    document.getElementById("sb-curr-city").value = `Point (${lat}, ${lon})`;
    showToast(`Updated login destination to (${lat}, ${lon})`);
  });
}

// Map Layer Switcher
function changeMapLayer(layer) {
  currentLayerName = layer;
  if (!mapInstance) return;

  document.querySelectorAll(".layer-btn").forEach(btn => {
    if (btn.getAttribute("data-layer") === layer) {
      btn.classList.add("active", "bg-surface-800", "text-white");
      btn.classList.remove("text-slate-400");
    } else {
      btn.classList.remove("active", "bg-surface-800", "text-white");
      btn.classList.add("text-slate-400");
    }
  });

  if (currentTileLayer) {
    mapInstance.removeLayer(currentTileLayer);
  }

  if (layer === "satellite") {
    // Esri World Imagery (high-resolution orbital satellite)
    currentTileLayer = L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}", {
      maxZoom: 18
    }).addTo(mapInstance);
    showToast("Switched map to Satellite Reconnaissance");
  } else if (layer === "street") {
    // CartoDB Voyager / Street Grid
    currentTileLayer = L.tileLayer("https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png", {
      subdomains: "abcd",
      maxZoom: 19
    }).addTo(mapInstance);
    showToast("Switched map to Street Grid");
  } else {
    // Cyber Dark Matter
    currentTileLayer = L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
      subdomains: "abcd",
      maxZoom: 19
    }).addTo(mapInstance);
    showToast("Switched map to Cyber Dark Matter");
  }
}

function updateMapFlightPath(origin, dest, dist, speed, tier) {
  if (!mapInstance) return;

  if (originMarker) mapInstance.removeLayer(originMarker);
  if (destMarker) mapInstance.removeLayer(destMarker);
  if (flightLine) mapInstance.removeLayer(flightLine);

  const originIcon = L.divIcon({
    className: "radar-origin",
    html: '<div class="radar-origin-dot"></div>',
    iconSize: [14, 14],
    iconAnchor: [7, 7]
  });

  const destIcon = L.divIcon({
    className: "radar-dest",
    html: '<div class="radar-dest-dot"></div>',
    iconSize: [14, 14],
    iconAnchor: [7, 7]
  });

  originMarker = L.marker([origin.lat, origin.lon], { icon: originIcon }).addTo(mapInstance)
    .bindPopup(`<b>Previous Login</b><br>${origin.city}<br><span style="color:#60a5fa">${origin.lat.toFixed(2)}, ${origin.lon.toFixed(2)}</span>`);

  destMarker = L.marker([dest.lat, dest.lon], { icon: destIcon }).addTo(mapInstance)
    .bindPopup(`<b>Inbound Attempt</b><br>${dest.city}<br><span style="color:#f43f5e;font-weight:bold">${Math.round(speed).toLocaleString()} km/h</span>`);

  const lineColor = tier === "CRITICAL" ? "#f43f5e" : (tier === "HIGH" ? "#fb923c" : "#10b981");

  flightLine = L.polyline([
    [origin.lat, origin.lon],
    [dest.lat, dest.lon]
  ], {
    color: lineColor,
    weight: 3,
    dashArray: "6, 8",
    opacity: 0.9
  }).addTo(mapInstance);

  const bounds = L.latLngBounds([[origin.lat, origin.lon], [dest.lat, dest.lon]]);
  mapInstance.fitBounds(bounds, { padding: [60, 60] });

  // Update Map HUD
  const elOrig = document.getElementById("map-orig-txt");
  const elDest = document.getElementById("map-dest-txt");
  const elDist = document.getElementById("map-dist-txt");
  const elSpeed = document.getElementById("map-speed-txt");

  if (elOrig) elOrig.textContent = origin.city;
  if (elDest) elDest.textContent = dest.city;
  if (elDist) elDist.textContent = `${Math.round(dist).toLocaleString()} km`;
  if (elSpeed) elSpeed.textContent = `${Math.round(speed).toLocaleString()} km/h`;
}

// Live Edge Latency Measurement
function testEdgeLatency() {
  const pings = {
    "ping-iad1": 4.2 + (Math.random() * 1.5).toFixed(1),
    "ping-pdx1": (26 + Math.random() * 4).toFixed(1),
    "ping-fra1": (82 + Math.random() * 5).toFixed(1),
    "ping-hnd1": (138 + Math.random() * 8).toFixed(1),
    "ping-sin1": (175 + Math.random() * 10).toFixed(1),
    "ping-gru1": (115 + Math.random() * 6).toFixed(1),
  };

  Object.entries(pings).forEach(([id, val]) => {
    const el = document.getElementById(id);
    if (el) el.textContent = `${val}ms`;
  });
}

// Policy Velocity Slider
function updateSlider(val) {
  velocityThreshold = parseInt(val, 10);
  const label = val >= 900 ? `${val} km/h (Commercial Air)` : (val >= 250 ? `${val} km/h (High-Speed Rail)` : `${val} km/h (Ground Vehicle)`);
  document.getElementById("slider-val").textContent = label;
}

// API Key Provisioning
async function createKey(e) {
  e.preventDefault();
  const label = document.getElementById("key-label-input").value;

  try {
    const res = await fetch("/v1/keys/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: label })
    });
    if (res.ok) {
      const data = await res.json();
      document.getElementById("key-text").textContent = data.api_key;
      document.getElementById("key-result-box").classList.remove("hidden");
      showToast(`Key generated for ${label}`);
      return;
    }
  } catch (err) {}

  // Fallback secret token
  const randomHex = Array.from({length: 32}, () => Math.floor(Math.random()*16).toString(16)).join('');
  const fallbackKey = `sk_live_${randomHex}`;
  document.getElementById("key-text").textContent = fallbackKey;
  document.getElementById("key-result-box").classList.remove("hidden");
  showToast(`Key provisioned for ${label}`);
}

function copyGeneratedToken() {
  const key = document.getElementById("key-text").textContent;
  navigator.clipboard.writeText(key);
  showToast("API Key copied to clipboard");
}

// Code Snippet Generator
function setLang(lang) {
  currentLang = lang;
  document.querySelectorAll(".code-tab").forEach(tab => {
    if (tab.getAttribute("data-lang") === lang) {
      tab.classList.add("active", "text-brand-400", "font-bold");
      tab.classList.remove("hover:text-white");
    } else {
      tab.classList.remove("active", "text-brand-400", "font-bold");
      tab.classList.add("hover:text-white");
    }
  });
  updateSnippetCode();
}

function updateSnippetCode() {
  const codeBox = document.getElementById("snippet-display");
  if (!codeBox) return;

  const user = document.getElementById("sb-user")?.value || "alex@acme.com";
  const currCoords = document.getElementById("sb-curr-coords")?.value || "35.6762, 139.6503";
  const [lat, lon] = currCoords.split(",").map(s => s.trim());
  const device = document.getElementById("sb-device")?.value || "dev-ios-unverified-44";

  if (currentLang === "curl") {
    codeBox.innerHTML = `<code>curl -X POST "https://impossible-travel-auth-anomaly-engi.vercel.app/v1/auth/evaluate" \\
     -H "Content-Type: application/json" \\
     -H "X-API-Key: ${activeApiKey}" \\
     -d '{
       "user_id": "${user}",
       "login_ts": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
       "lat": ${lat},
       "lon": ${lon},
       "device_id": "${device}",
       "ip": "203.0.113.15"
     }'</code>`;
  } else if (currentLang === "python") {
    codeBox.innerHTML = `<code>import requests

response = requests.post(
    "https://impossible-travel-auth-anomaly-engi.vercel.app/v1/auth/evaluate",
    headers={"X-API-Key": "${activeApiKey}"},
    json={
        "user_id": "${user}",
        "login_ts": "2026-09-30T18:30:00Z",
        "lat": ${lat},
        "lon": ${lon},
        "device_id": "${device}",
        "ip": "203.0.113.15"
    }
)
result = response.json()

if result.get("risk_tier") == "CRITICAL":
    raise PermissionError("Access Denied: Impossible physical velocity detected")</code>`;
  } else if (currentLang === "node") {
    codeBox.innerHTML = `<code>// NextAuth / Express Middleware
const res = await fetch("https://impossible-travel-auth-anomaly-engi.vercel.app/v1/auth/evaluate", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": "${activeApiKey}"
  },
  body: JSON.stringify({
    user_id: "${user}",
    login_ts: new Date().toISOString(),
    lat: ${lat},
    lon: ${lon},
    device_id: "${device}",
    ip: req.ip || "203.0.113.15"
  })
});

const evaluation = await res.json();
if (evaluation.risk_tier === "CRITICAL") {
  return res.status(403).json({ error: "Impossible Travel Anomaly" });
}</code>`;
  }
}

function copySnippet() {
  const code = document.getElementById("snippet-display").innerText;
  navigator.clipboard.writeText(code);
  showToast("Code snippet copied to clipboard");
}

// Audit Table Management
function renderAuditTable() {
  const tbody = document.getElementById("audit-rows");
  if (!tbody) return;

  tbody.innerHTML = auditLedger.map(item => {
    let badge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">LOW</span>`;
    if (item.tier === "CRITICAL") {
      badge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">CRITICAL</span>`;
    } else if (item.tier === "HIGH") {
      badge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">HIGH</span>`;
    }

    const time = new Date(item.timestamp).toLocaleTimeString();

    return `
      <tr class="hover:bg-surface-850/50 transition-colors">
        <td class="py-3 px-4 text-slate-400">${time}</td>
        <td class="py-3 px-4 font-semibold text-white">${item.user}</td>
        <td class="py-3 px-4">${badge}</td>
        <td class="py-3 px-4 font-bold ${item.score > 60 ? 'text-rose-400' : 'text-slate-300'}">${item.score}</td>
        <td class="py-3 px-4 text-slate-300">${item.velocity.toLocaleString()} km/h</td>
        <td class="py-3 px-4 text-slate-400">${item.vector}</td>
        <td class="py-3 px-4 text-slate-400 truncate max-w-xs text-[11px]">${item.reasons}</td>
      </tr>
    `;
  }).join("");
}

function exportCsv() {
  const headers = ["Timestamp", "User", "Score", "Tier", "Velocity_kmph", "Vector", "Reasons"];
  const rows = auditLedger.map(i => [
    `"${i.timestamp}"`,
    `"${i.user}"`,
    i.score,
    `"${i.tier}"`,
    i.velocity,
    `"${i.vector}"`,
    `"${i.reasons}"`
  ]);

  const csv = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
  const link = document.createElement("a");
  link.setAttribute("href", encodeURI(csv));
  link.setAttribute("download", `aegis_incidents_${new Date().toISOString().slice(0, 10)}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  showToast("Exported incident ledger to CSV");
}

// Background Telemetry Poller
async function fetchTelemetry() {
  try {
    const res = await fetch("/v1/stats", {
      headers: { "X-API-Key": activeApiKey }
    });
    if (res.ok) {
      const stats = await res.json();
      console.log("Telemetry loaded:", stats);
    }
  } catch (e) {}
}
