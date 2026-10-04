// Aegis dashboard: every verdict, score and reason on this page comes from the live API.

let currentSection = 'sandbox';
const MASTER_KEY = 'demo-master-key-9000';
let activeApiKey = MASTER_KEY;
let currentLang = 'curl';
let mapInstance = null;
let currentTileLayer = null;
let originMarker = null;
let destMarker = null;
let flightLine = null;
let currentLayerName = 'dark';
let lastFlight = null;
const KNOWN_DEVICE = 'dev-known-laptop';
const auditLedger = [];

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const TIER_STYLE = {
  LOW: { badge: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20', bar: 'bg-emerald-500', text: 'text-emerald-400', icon: '✅', line: '#10b981' },
  MEDIUM: { badge: 'bg-amber-500/10 text-amber-300 border border-amber-500/20', bar: 'bg-amber-400', text: 'text-amber-300', icon: '🟡', line: '#fbbf24' },
  HIGH: { badge: 'bg-orange-500/10 text-orange-400 border border-orange-500/20', bar: 'bg-orange-500 shadow-[0_0_12px_#fb923c]', text: 'text-orange-400', icon: '⚠️', line: '#fb923c' },
  CRITICAL: { badge: 'bg-rose-500/10 text-rose-400 border border-rose-500/20', bar: 'bg-rose-500 shadow-[0_0_12px_#f43f5e]', text: 'text-rose-400', icon: '🚨', line: '#f43f5e' },
};

document.addEventListener("DOMContentLoaded", () => {
  renderAuditTable();
  updateSnippetCode();
  loadModelCard();
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
  const sections = ["sandbox", "radar", "policy", "audit"];
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


// Preset scenarios (sample accounts; coordinates are real city locations)
function pickPreset(preset) {
  const set = (id, v) => { document.getElementById(id).value = v; };
  const P = {
    nyc_tokyo: ["alex.executive@acme.com", "New York, US", "40.7128, -74.0060", "Tokyo, JP", "35.6762, 139.6503", 5, "dev-ios-unverified-44"],
    london_sydney: ["sarah.lead@acme.com", "London, GB", "51.5074, -0.1278", "Sydney, AU", "-33.8688, 151.2093", 10, "dev-android-unknown-99"],
    frankfurt_zurich: ["dev.ops@acme.com", "Frankfurt, DE", "50.1109, 8.6821", "Zurich, CH", "47.3769, 8.5417", 15, "dev-tor-relay-node"],
    sf_commute: ["emily.staff@acme.com", "San Francisco, US", "37.7749, -122.4194", "San Jose, US", "37.3382, -121.8863", 45, KNOWN_DEVICE],
  }[preset];
  ["sb-user", "sb-prev-city", "sb-prev-coords", "sb-curr-city", "sb-curr-coords", "sb-minutes", "sb-device"].forEach((id, i) => set(id, P[i]));
  showToast(`Loaded preset: ${preset.replace('_', ' ').toUpperCase()}`);
  runEvaluation();
}

function resetSandboxInputs() {
  document.getElementById("sandbox-form").reset();
  showToast("Reset form to default values");
}

const parseCoords = s => s.split(",").map(x => parseFloat(x.trim()));
const countryOf = city => (city.split(",")[1] || "").trim().toUpperCase() || null;

async function postLogin(event) {
  const res = await fetch("/v1/auth/evaluate", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-API-Key": activeApiKey },
    body: JSON.stringify(event),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail));
  return data;
}

// Live evaluation: send the account's history, then the login being tested, and render the API's answer.
async function runEvaluation(e) {
  if (e) e.preventDefault();
  const user = document.getElementById("sb-user").value;
  const prevCity = document.getElementById("sb-prev-city").value;
  const currCity = document.getElementById("sb-curr-city").value;
  const [lat1, lon1] = parseCoords(document.getElementById("sb-prev-coords").value);
  const [lat2, lon2] = parseCoords(document.getElementById("sb-curr-coords").value);
  const minutes = Math.max(1, parseFloat(document.getElementById("sb-minutes").value) || 5);
  const device = document.getElementById("sb-device").value.trim() || KNOWN_DEVICE;
  const userId = `${user}#demo-${Date.now().toString(36)}`;  // fresh history for every run
  const now = Date.now();
  const base = { user_id: userId, ip: "198.51.100.20", device_id: KNOWN_DEVICE, asn: 29695, rtt_ms: 420, success: true };
  const btn = document.getElementById("btn-eval");
  if (btn) btn.disabled = true;
  try {
    for (let d = 5; d >= 1; d--) {
      await postLogin({ ...base, login_ts: new Date(now - minutes * 60000 - d * 86400000).toISOString(),
        country: countryOf(prevCity), city: prevCity.split(",")[0].trim(), lat: lat1, lon: lon1 });
    }
    await postLogin({ ...base, login_ts: new Date(now - minutes * 60000).toISOString(),
      country: countryOf(prevCity), city: prevCity.split(",")[0].trim(), lat: lat1, lon: lon1 });
    const known = device === KNOWN_DEVICE;
    const t0 = performance.now();
    const r = await postLogin({ ...base, login_ts: new Date(now).toISOString(), country: countryOf(currCity),
      city: currCity.split(",")[0].trim(), lat: lat2, lon: lon2, device_id: device,
      asn: known ? 29695 : 9009, ip: known ? "198.51.100.20" : "203.0.113.15" });
    const ms = (performance.now() - t0).toFixed(1);
    document.getElementById("eval-runtime").textContent = `Round-trip: ${ms}ms`;
    document.getElementById("latency-badge").textContent = `${ms}ms`;
    renderVerdict(r, prevCity, currCity, minutes);
    auditLedger.unshift({ timestamp: new Date().toISOString(), user, score: r.risk_score, tier: r.risk_tier,
      velocity: Math.round(r.velocity_kmph), vector: `${prevCity} → ${currCity}`, reasons: r.reasons.join("; ") });
    if (auditLedger.length > 50) auditLedger.pop();
    renderAuditTable();
    lastFlight = [{ lat: lat1, lon: lon1, city: prevCity }, { lat: lat2, lon: lon2, city: currCity }, r];
    updateMapFlightPath(...lastFlight);
    updateSnippetCode();
    showToast(`API verdict: ${r.risk_tier}`);
  } catch (err) {
    showToast(`Evaluation failed: ${err.message}`, false);
  } finally {
    if (btn) btn.disabled = false;
  }
}

function renderVerdict(r, prevCity, currCity, minutes) {
  const st = TIER_STYLE[r.risk_tier];
  const badge = document.getElementById("human-badge");
  badge.className = `px-2.5 py-0.5 rounded-full text-xs font-bold ${st.badge}`;
  badge.textContent = `${r.risk_tier} RISK`;
  document.getElementById("verdict-headline").innerHTML =
    `<span class="${st.text} text-lg">${st.icon}</span> <span>Recommended action: ${esc(r.recommended_action)}</span>`;
  document.getElementById("verdict-narrative").innerHTML =
    `Login from <strong>${esc(currCity)}</strong> ${esc(minutes)} minutes after one from <strong>${esc(prevCity)}</strong> ` +
    `(${Math.round(r.distance_km).toLocaleString()} km, ${Math.round(r.velocity_kmph).toLocaleString()} km/h). ` +
    `The models rate it riskier than <strong>${r.risk_score.toFixed(2)}%</strong> of real validation logins ` +
    `(takeover percentile ${r.ato_percentile.toFixed(2)}, attack-IP percentile ${r.attack_ip_percentile.toFixed(2)}).`;
  const bar = document.getElementById("velocity-bar");
  bar.className = `h-full rounded-full transition-all duration-700 ${st.bar}`;
  bar.style.width = `${Math.min(100, (r.velocity_kmph / 900) * 66)}%`;
  document.getElementById("hud-score").innerHTML = `${r.risk_score.toFixed(1)}<span class="text-xs text-slate-500 font-normal">/100</span>`;
  document.getElementById("hud-score").className = `text-xl sm:text-2xl font-black ${st.text} mt-0.5`;
  document.getElementById("hud-velocity").textContent = `${Math.round(r.velocity_kmph).toLocaleString()} km/h`;
  document.getElementById("hud-distance").textContent = `${Math.round(r.distance_km).toLocaleString()} km`;
  const action = document.getElementById("hud-action");
  action.textContent = r.recommended_action.toUpperCase();
  action.className = `text-xs sm:text-sm font-bold ${st.text} mt-2`;
  document.getElementById("reasons-list").innerHTML = `
    <div class="text-xs font-mono text-slate-400">Reasons returned by the API:</div>
    ${r.reasons.map(t => `
      <div class="flex items-center gap-2 text-xs font-mono text-slate-200 p-2 rounded bg-surface-950 border border-surface-800">
        <span class="${st.text} font-bold">●</span><span>${esc(t)}</span>
      </div>`).join("")}`;
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
    attributionControl: true,
    minZoom: 2,
    maxZoom: 14
  }).setView([30, 10], 2);

  // Default Dark Matter Layer
  currentTileLayer = L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 19, attribution: "&copy; OpenStreetMap contributors", className: "tiles-dark" }).addTo(mapInstance);

  if (lastFlight) updateMapFlightPath(...lastFlight);

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
      maxZoom: 18, attribution: "Tiles &copy; Esri"
    }).addTo(mapInstance);
    showToast("Switched map to Satellite Reconnaissance");
  } else if (layer === "street") {
    // CartoDB Voyager / Street Grid
    currentTileLayer = L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 19, attribution: "&copy; OpenStreetMap contributors" }).addTo(mapInstance);
    showToast("Switched map to Street Grid");
  } else {
    // Cyber Dark Matter
    currentTileLayer = L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 19, attribution: "&copy; OpenStreetMap contributors", className: "tiles-dark" }).addTo(mapInstance);
    showToast("Switched map to Cyber Dark Matter");
  }
}

function updateMapFlightPath(origin, dest, r) {
  const dist = r.distance_km, speed = r.velocity_kmph, tier = r.risk_tier;
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
    .bindPopup(`<b>Previous Login</b><br>${esc(origin.city)}<br><span style="color:#60a5fa">${origin.lat.toFixed(2)}, ${origin.lon.toFixed(2)}</span>`);

  destMarker = L.marker([dest.lat, dest.lon], { icon: destIcon }).addTo(mapInstance)
    .bindPopup(`<b>Login Being Scored</b><br>${esc(dest.city)}<br><span style="color:#f43f5e;font-weight:bold">${Math.round(speed).toLocaleString()} km/h</span>`);

  const lineColor = TIER_STYLE[tier].line;

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
  const elVerdict = document.getElementById("map-verdict-txt");
  if (elVerdict) { elVerdict.textContent = `${tier}: ${r.recommended_action}`; elVerdict.className = `${TIER_STYLE[tier].text} font-black`; }
}


// API key issuing (real endpoint; requires the master key)
async function createKey(e) {
  e.preventDefault();
  const label = document.getElementById("key-label-input").value;
  try {
    const res = await fetch("/v1/keys/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": MASTER_KEY },
      body: JSON.stringify({ name: label }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || res.statusText);
    activeApiKey = data.api_key;
    document.getElementById("key-text").textContent = data.api_key;
    document.getElementById("key-result-box").classList.remove("hidden");
    updateSnippetCode();
    showToast(`Key issued for ${label}`);
  } catch (err) {
    showToast(`Key request failed: ${err.message}`, false);
  }
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
       "country": "JP",
       "asn": 9009,
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


// Audit table: logins scored in this browser session
function renderAuditTable() {
  const tbody = document.getElementById("audit-rows");
  if (!tbody) return;
  if (!auditLedger.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="py-4 px-4 text-slate-500">No logins scored yet. Run a scenario in the sandbox.</td></tr>`;
    return;
  }
  tbody.innerHTML = auditLedger.map(item => `
      <tr class="hover:bg-surface-850/50 transition-colors">
        <td class="py-3 px-4 text-slate-400">${new Date(item.timestamp).toLocaleTimeString()}</td>
        <td class="py-3 px-4 font-semibold text-white">${esc(item.user)}</td>
        <td class="py-3 px-4"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${TIER_STYLE[item.tier].badge}">${item.tier}</span></td>
        <td class="py-3 px-4 font-bold ${TIER_STYLE[item.tier].text}">${item.score.toFixed(1)}</td>
        <td class="py-3 px-4 text-slate-300">${item.velocity.toLocaleString()} km/h</td>
        <td class="py-3 px-4 text-slate-400">${esc(item.vector)}</td>
        <td class="py-3 px-4 text-slate-400 truncate max-w-xs text-[11px]">${esc(item.reasons)}</td>
      </tr>`).join("");
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


// Real held-out metrics of the deployed models
async function loadModelCard() {
  const tile = (label, value) => `<div class="p-3 bg-surface-950 rounded-xl border border-surface-800"><div class="text-[10px] text-slate-400 uppercase">${label}</div><div class="text-lg font-black text-white mt-0.5">${value}</div></div>`;
  const pct = v => `${(v * 100).toFixed(2)}%`;
  try {
    const m = await (await fetch("/v1/model")).json();
    const a = m.test_metrics.ato, k = m.test_metrics.attack_ip;
    document.getElementById("card-ato").innerHTML = tile("ROC-AUC", a.roc_auc.toFixed(3)) + tile("Takeovers caught", `${a.confusion_matrix.tp} of ${a.positives}`) +
      tile("Logins challenged", pct(a.alert_rate)) + tile("Test logins", a.logins.toLocaleString());
    document.getElementById("card-atk").innerHTML = tile("ROC-AUC", k.roc_auc.toFixed(3)) + tile("PR-AUC", k.pr_auc.toFixed(3)) +
      tile("Precision / recall", `${pct(k.precision)} / ${pct(k.recall)}`) + tile("Test logins", k.logins.toLocaleString());
    document.getElementById("card-note").textContent = `Dataset: ${m.dataset.name}. ${m.dataset.note}`;
  } catch (err) {
    document.getElementById("card-note").textContent = "Could not load the model card.";
  }
}
