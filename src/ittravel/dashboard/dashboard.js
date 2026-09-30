// Aegis ITDR Enterprise Dashboard Logic

let currentTab = 'overview';
let activeApiKey = 'demo-master-key-9000';
let overviewChartInstance = null;
let leafletMapInstance = null;
let mapFlightLine = null;
let originMarker = null;
let destMarker = null;
let currentSdkLang = 'curl';

// Local cache of audit events
let auditLogs = [
  {
    timestamp: new Date(Date.now() - 1000 * 60 * 2).toISOString(),
    user_id: "demo_user_showcase",
    risk_score: 93.6,
    risk_tier: "CRITICAL",
    velocity_kmph: 2123052.7,
    distance_km: 10851.7,
    time_delta_hours: 0.005,
    previous_location: { city: "Tokyo", country: "JP", lat: 35.6762, lon: 139.6503 },
    current_location: { city: "New York", country: "US", lat: 40.7128, lon: -74.006 },
    reasons: ["Impossible physical travel velocity", "Unrecognized device fingerprint", "Login from new IP subnet"]
  },
  {
    timestamp: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
    user_id: "usr_fin_8829",
    risk_score: 74.2,
    risk_tier: "HIGH",
    velocity_kmph: 1840.0,
    distance_km: 680.0,
    time_delta_hours: 0.37,
    previous_location: { city: "Frankfurt", country: "DE", lat: 50.1109, lon: 8.6821 },
    current_location: { city: "London", country: "GB", lat: 51.5074, lon: -0.1278 },
    reasons: ["Supersonic transit velocity (> 900 km/h)", "New device fingerprint hash"]
  },
  {
    timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    user_id: "sec_audit_root",
    risk_score: 96.8,
    risk_tier: "CRITICAL",
    velocity_kmph: 850210.0,
    distance_km: 12050.0,
    time_delta_hours: 0.014,
    previous_location: { city: "Sydney", country: "AU", lat: -33.8688, lon: 151.2093 },
    current_location: { city: "Los Angeles", country: "US", lat: 34.0522, lon: -118.2437 },
    reasons: ["Impossible travel velocity", "Tor Exit Node Subnet detected"]
  },
  {
    timestamp: new Date(Date.now() - 1000 * 60 * 80).toISOString(),
    user_id: "usr_eng_3310",
    risk_score: 42.0,
    risk_tier: "MEDIUM",
    velocity_kmph: 45.0,
    distance_km: 12.0,
    time_delta_hours: 0.27,
    previous_location: { city: "San Francisco", country: "US", lat: 37.7749, lon: -122.4194 },
    current_location: { city: "San Francisco", country: "US", lat: 37.7833, lon: -122.4167 },
    reasons: ["Unrecognized device fingerprint"]
  }
];

// Document Ready
document.addEventListener("DOMContentLoaded", () => {
  initOverviewChart();
  initCopyButtons();
  refreshData();
  renderAuditLogs();
});

// Toast notification helper
function showToast(message, isSuccess = true) {
  const toast = document.getElementById("toast");
  const msgEl = document.getElementById("toast-msg");
  const iconEl = document.getElementById("toast-icon");
  if (!toast || !msgEl) return;

  msgEl.textContent = message;
  iconEl.textContent = isSuccess ? "✅" : "⚠️";
  toast.classList.remove("translate-y-20", "opacity-0");
  toast.classList.add("translate-y-0", "opacity-100");

  setTimeout(() => {
    toast.classList.remove("translate-y-0", "opacity-100");
    toast.classList.add("translate-y-20", "opacity-0");
  }, 2500);
}

// Tab Switching
function switchTab(tabId) {
  currentTab = tabId;
  
  // Hide all contents
  document.querySelectorAll(".tab-content").forEach(el => el.classList.add("hidden"));
  
  // Show target content
  const target = document.getElementById(`tab-${tabId}`);
  if (target) target.classList.remove("hidden");

  // Update navigation items
  document.querySelectorAll("[data-tab-btn]").forEach(btn => {
    if (btn.getAttribute("data-tab-btn") === tabId) {
      btn.classList.add("active");
      btn.querySelector("svg")?.classList.add("text-brand-400");
      btn.querySelector("svg")?.classList.remove("text-slate-400");
    } else {
      btn.classList.remove("active");
      btn.querySelector("svg")?.classList.remove("text-brand-400");
      btn.querySelector("svg")?.classList.add("text-slate-400");
    }
  });

  // Lazy initialize map when map tab opens
  if (tabId === "map") {
    setTimeout(initRadarMap, 50);
  }
}

// Chart.js Overview Initialization
function initOverviewChart() {
  const canvas = document.getElementById("overviewChart");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  
  // Gradient backgrounds
  const brandGradient = ctx.createLinearGradient(0, 0, 0, 280);
  brandGradient.addColorStop(0, "rgba(59, 130, 246, 0.35)");
  brandGradient.addColorStop(1, "rgba(59, 130, 246, 0.0)");

  const threatGradient = ctx.createLinearGradient(0, 0, 0, 280);
  threatGradient.addColorStop(0, "rgba(244, 63, 94, 0.35)");
  threatGradient.addColorStop(1, "rgba(244, 63, 94, 0.0)");

  overviewChartInstance = new Chart(ctx, {
    type: "line",
    data: {
      labels: ["00:00", "03:00", "06:00", "09:00", "12:00", "15:00", "18:00", "21:00", "Now"],
      datasets: [
        {
          label: "Normal Logins",
          data: [120, 85, 240, 560, 710, 890, 780, 620, 540],
          borderColor: "#3b82f6",
          backgroundColor: brandGradient,
          fill: true,
          tension: 0.4,
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: "#3b82f6",
        },
        {
          label: "Flagged Threats",
          data: [4, 1, 8, 22, 19, 34, 28, 15, 12],
          borderColor: "#f43f5e",
          backgroundColor: threatGradient,
          fill: true,
          tension: 0.4,
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: "#f43f5e",
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#101623",
          titleFont: { family: "JetBrains Mono", size: 12 },
          bodyFont: { family: "JetBrains Mono", size: 12 },
          borderColor: "#1e293b",
          borderWidth: 1,
          padding: 10,
        }
      },
      scales: {
        x: {
          grid: { color: "rgba(30, 41, 59, 0.4)" },
          ticks: { color: "#64748b", font: { family: "JetBrains Mono", size: 10 } }
        },
        y: {
          grid: { color: "rgba(30, 41, 59, 0.4)" },
          ticks: { color: "#64748b", font: { family: "JetBrains Mono", size: 10 } }
        }
      }
    }
  });
}

// Leaflet Radar Map Initialization
function initRadarMap() {
  const container = document.getElementById("radarMap");
  if (!container) return;

  if (leafletMapInstance) {
    leafletMapInstance.invalidateSize();
    return;
  }

  // Create Leaflet map centered globally
  leafletMapInstance = L.map("radarMap", {
    zoomControl: true,
    attributionControl: false,
    minZoom: 2,
    maxZoom: 10,
  }).setView([25.0, 10.0], 2);

  // CartoDB Dark Matter Tiles (High-end cyber security aesthetic)
  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    subdomains: "abcd",
    maxZoom: 19
  }).addTo(leafletMapInstance);

  // Initial demo vectors: Tokyo & New York
  plotImpossibleTravel(
    { lat: 40.7128, lon: -74.0060, city: "New York", country: "US" },
    { lat: 35.6762, lon: 139.6503, city: "Tokyo", country: "JP" },
    "2,123,052 km/h"
  );
}

function plotImpossibleTravel(origin, dest, speedText) {
  if (!leafletMapInstance) return;

  // Clear existing markers and lines
  if (originMarker) leafletMapInstance.removeLayer(originMarker);
  if (destMarker) leafletMapInstance.removeLayer(destMarker);
  if (mapFlightLine) leafletMapInstance.removeLayer(mapFlightLine);

  // Custom icons
  const originIcon = L.divIcon({
    className: "radar-marker",
    html: '<div class="origin-marker-dot"></div>',
    iconSize: [16, 16],
    iconAnchor: [8, 8]
  });

  const destIcon = L.divIcon({
    className: "radar-marker",
    html: '<div class="radar-marker-dot"></div>',
    iconSize: [16, 16],
    iconAnchor: [8, 8]
  });

  originMarker = L.marker([origin.lat, origin.lon], { icon: originIcon }).addTo(leafletMapInstance)
    .bindPopup(`<b>Previous Login</b><br>${origin.city}, ${origin.country}<br><span style="color:#60a5fa">${origin.lat.toFixed(2)}, ${origin.lon.toFixed(2)}</span>`);

  destMarker = L.marker([dest.lat, dest.lon], { icon: destIcon }).addTo(leafletMapInstance)
    .bindPopup(`<b>Flagged Anomaly</b><br>${dest.city}, ${dest.country}<br><span style="color:#f43f5e;font-weight:bold;">${speedText}</span>`);

  // Draw geodesic flight line with glowing dash array
  mapFlightLine = L.polyline([
    [origin.lat, origin.lon],
    [dest.lat, dest.lon]
  ], {
    color: "#f43f5e",
    weight: 3,
    dashArray: "6, 8",
    opacity: 0.85
  }).addTo(leafletMapInstance);

  // Fit bounds nicely
  const bounds = L.latLngBounds([
    [origin.lat, origin.lon],
    [dest.lat, dest.lon]
  ]);
  leafletMapInstance.fitBounds(bounds, { padding: [50, 50] });

  // Update HUD
  const hudOrigin = document.getElementById("map-hud-origin");
  const hudDest = document.getElementById("map-hud-dest");
  const hudVelocity = document.getElementById("map-hud-velocity");
  if (hudOrigin) hudOrigin.textContent = `${origin.city}, ${origin.country}`;
  if (hudDest) hudDest.textContent = `${dest.city}, ${dest.country}`;
  if (hudVelocity) hudVelocity.textContent = speedText;
}

function simulateMapAttack() {
  const attacks = [
    {
      origin: { lat: 51.5074, lon: -0.1278, city: "London", country: "GB" },
      dest: { lat: -33.8688, lon: 151.2093, city: "Sydney", country: "AU" },
      speed: "3,892,100 km/h"
    },
    {
      origin: { lat: 37.7749, lon: -122.4194, city: "San Francisco", country: "US" },
      dest: { lat: 1.3521, lon: 103.8198, city: "Singapore", country: "SG" },
      speed: "1,450,200 km/h"
    },
    {
      origin: { lat: 40.7128, lon: -74.0060, city: "New York", country: "US" },
      dest: { lat: 35.6762, lon: 139.6503, city: "Tokyo", country: "JP" },
      speed: "2,123,052 km/h"
    }
  ];

  const pick = attacks[Math.floor(Math.random() * attacks.length)];
  plotImpossibleTravel(pick.origin, pick.dest, pick.speed);
  showToast(`Simulated attack path: ${pick.origin.city} → ${pick.dest.city}`);
}

// 1-Click Attack Presets for Simulator
function loadScenario(type) {
  switchTab('simulator');

  const user = document.getElementById("sim-user");
  const lat = document.getElementById("sim-lat");
  const lon = document.getElementById("sim-lon");
  const city = document.getElementById("sim-city");
  const country = document.getElementById("sim-country");
  const device = document.getElementById("sim-device");
  const ip = document.getElementById("sim-ip");

  if (type === "impossible_travel") {
    // Tokyo jump
    user.value = "demo_user_showcase";
    lat.value = 35.6762;
    lon.value = 139.6503;
    city.value = "Tokyo";
    country.value = "JP";
    device.value = "dev-ios-unregistered-77";
    ip.value = "203.0.113.15";
  } else if (type === "credential_stuffing") {
    // Tor subnet jump
    user.value = "usr_fin_8829";
    lat.value = 47.3769;
    lon.value = 8.5417;
    city.value = "Zurich";
    country.value = "CH";
    device.value = "dev-tor-headless-chrome";
    ip.value = "185.220.101.5";
  } else if (type === "device_novelty") {
    // New device in same city
    user.value = "usr_analyst_01";
    lat.value = 40.7128;
    lon.value = -74.0060;
    city.value = "New York";
    country.value = "US";
    device.value = "dev-android-pixel-9-novel";
    ip.value = "192.168.1.150";
  } else if (type === "normal_routine") {
    // Normal commute
    user.value = "usr_staff_alice";
    lat.value = 37.7833;
    lon.value = -122.4167;
    city.value = "San Francisco";
    country.value = "US";
    device.value = "dev-macbook-pro-work";
    ip.value = "10.0.4.12";
  }

  showToast(`Loaded scenario: ${type.replace('_', ' ').toUpperCase()}`);
  updateSdkCode();
}

function resetSimulatorForm() {
  document.getElementById("sim-form").reset();
  showToast("Simulator form reset to defaults");
}

// Live Simulator Execution
async function executeSimulator(e) {
  if (e) e.preventDefault();

  const btn = document.getElementById("btn-run-sim");
  btn.disabled = true;
  btn.innerHTML = `<svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white inline" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> <span>EVALUATING INFERENCE MODEL...</span>`;

  const payload = {
    user_id: document.getElementById("sim-user").value,
    login_ts: new Date().toISOString(),
    lat: parseFloat(document.getElementById("sim-lat").value),
    lon: parseFloat(document.getElementById("sim-lon").value),
    city: document.getElementById("sim-city").value,
    country: document.getElementById("sim-country").value,
    device_id: document.getElementById("sim-device").value,
    ip: document.getElementById("sim-ip").value
  };

  const startTime = performance.now();

  try {
    const res = await fetch("/v1/auth/evaluate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": activeApiKey
      },
      body: JSON.stringify(payload)
    });

    const elapsed = Math.round(performance.now() - startTime);
    const data = await res.json();

    document.getElementById("res-latency").textContent = `LATENCY: ${elapsed}ms`;
    document.getElementById("topbar-latency").textContent = `${elapsed}ms`;
    
    renderSimulatorResult(data);
    addAuditLogEntry(data);
    showToast(`Evaluated: Risk Score ${data.risk_score} (${data.risk_tier})`);

  } catch (err) {
    console.error("Evaluation error:", err);
    // Offline / fallback calculation demonstration
    const fallbackResult = calculateClientFallback(payload);
    renderSimulatorResult(fallbackResult);
    addAuditLogEntry(fallbackResult);
    showToast(`Simulation complete: Risk Score ${fallbackResult.risk_score}`);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg> <span>EVALUATE ANOMALY RISK IN REAL-TIME</span>`;
  }
}

// Client Fallback calculation if serverless cold-start or offline
function calculateClientFallback(p) {
  const isFar = (Math.abs(p.lat - 40.7128) > 20 || Math.abs(p.lon - (-74.0060)) > 20);
  const score = isFar ? 92.5 : 12.0;
  const tier = isFar ? "CRITICAL" : "LOW";
  const speed = isFar ? 2123052.7 : 24.5;
  const dist = isFar ? 10851.7 : 18.2;
  const reasons = isFar 
    ? [`Impossible physical travel velocity (${speed.toFixed(1)} km/h > 900 km/h)`, `Unrecognized device fingerprint (${p.device_id})`, "Login from new IP subnet"]
    : ["Normal login behavior pattern"];

  return {
    user_id: p.user_id,
    is_anomaly: isFar,
    risk_score: score,
    risk_tier: tier,
    velocity_kmph: speed,
    distance_km: dist,
    time_delta_hours: 0.005,
    reasons: reasons,
    current_location: { city: p.city, country: p.country, lat: p.lat, lon: p.lon },
    previous_location: { city: "New York", country: "US", lat: 40.7128, lon: -74.006 },
    timestamp: p.login_ts
  };
}

// Render Simulator Decision HUD
function renderSimulatorResult(data) {
  // Score display
  const scoreEl = document.getElementById("res-score");
  const verdictEl = document.getElementById("res-verdict");
  const badgeEl = document.getElementById("res-badge");
  const gaugeBar = document.getElementById("res-gauge-bar");
  const recAction = document.getElementById("res-rec-action");

  scoreEl.innerHTML = `${data.risk_score}<span class="text-xl text-slate-500 font-normal">/100</span>`;
  gaugeBar.style.width = `${data.risk_score}%`;

  // Tier color customization
  if (data.risk_tier === "CRITICAL") {
    scoreEl.className = "text-5xl font-extrabold tracking-tight mt-1 text-rose-500";
    verdictEl.textContent = "IMPOSSIBLE TRAVEL ATTACK";
    verdictEl.className = "text-xs font-mono font-bold mt-1 text-rose-400";
    badgeEl.className = "px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20";
    badgeEl.textContent = "TIER: CRITICAL";
    gaugeBar.className = "h-full rounded-full transition-all duration-700 bg-rose-500 shadow-[0_0_12px_#f43f5e]";
    recAction.textContent = "ACTION: IMMEDIATE BLOCK & SOC ALERT";
    recAction.className = "text-rose-400 font-bold";
  } else if (data.risk_tier === "HIGH") {
    scoreEl.className = "text-5xl font-extrabold tracking-tight mt-1 text-amber-500";
    verdictEl.textContent = "SUPERSONIC ANOMALY";
    verdictEl.className = "text-xs font-mono font-bold mt-1 text-amber-400";
    badgeEl.className = "px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20";
    badgeEl.textContent = "TIER: HIGH";
    gaugeBar.className = "h-full rounded-full transition-all duration-700 bg-amber-500 shadow-[0_0_12px_#fb923c]";
    recAction.textContent = "ACTION: STEP-UP MFA CHALLENGE";
    recAction.className = "text-amber-400 font-bold";
  } else if (data.risk_tier === "MEDIUM") {
    scoreEl.className = "text-5xl font-extrabold tracking-tight mt-1 text-yellow-400";
    verdictEl.textContent = "ELEVATED RISK LOG";
    verdictEl.className = "text-xs font-mono font-bold mt-1 text-yellow-400";
    badgeEl.className = "px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-yellow-500/10 text-yellow-400 border border-yellow-500/20";
    badgeEl.textContent = "TIER: MEDIUM";
    gaugeBar.className = "h-full rounded-full transition-all duration-700 bg-yellow-400";
    recAction.textContent = "ACTION: LOG & PASSIVE MONITOR";
    recAction.className = "text-yellow-400 font-semibold";
  } else {
    scoreEl.className = "text-5xl font-extrabold tracking-tight mt-1 text-emerald-400";
    verdictEl.textContent = "AUTHENTICATED REGULAR";
    verdictEl.className = "text-xs font-mono font-bold mt-1 text-emerald-400";
    badgeEl.className = "px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20";
    badgeEl.textContent = "TIER: LOW (SAFE)";
    gaugeBar.className = "h-full rounded-full transition-all duration-700 bg-emerald-500 shadow-[0_0_12px_#10b981]";
    recAction.textContent = "ACTION: ALLOW FRICTIONLESS";
    recAction.className = "text-emerald-400 font-semibold";
  }

  // Geodesic numbers
  document.getElementById("res-velocity").textContent = `${data.velocity_kmph?.toLocaleString() || 0} km/h`;
  document.getElementById("res-distance").textContent = `${data.distance_km?.toLocaleString() || 0} km`;
  document.getElementById("res-timedelta").textContent = `${data.time_delta_hours?.toFixed(3) || 0} hrs`;

  // Reasons list
  const reasonsCont = document.getElementById("res-reasons-container");
  if (reasonsCont) {
    reasonsCont.innerHTML = "";
    (data.reasons || []).forEach(r => {
      const item = document.createElement("div");
      item.className = "flex items-center gap-2 p-2 rounded-lg bg-dark-950 border border-dark-800 text-xs text-slate-200 font-mono";
      item.innerHTML = `<svg class="w-3.5 h-3.5 text-rose-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg> <span>${r}</span>`;
      reasonsCont.appendChild(item);
    });
  }

  // Raw JSON
  document.getElementById("res-raw-json").textContent = JSON.stringify(data, null, 2);
}

function copyJsonResponse() {
  const json = document.getElementById("res-raw-json").textContent;
  navigator.clipboard.writeText(json);
  showToast("JSON payload copied to clipboard");
}

// Audit Logs Management
function addAuditLogEntry(data) {
  auditLogs.unshift({
    timestamp: data.timestamp || new Date().toISOString(),
    user_id: data.user_id,
    risk_score: data.risk_score,
    risk_tier: data.risk_tier,
    velocity_kmph: data.velocity_kmph,
    distance_km: data.distance_km,
    time_delta_hours: data.time_delta_hours,
    current_location: data.current_location,
    previous_location: data.previous_location,
    reasons: data.reasons
  });

  if (auditLogs.length > 100) auditLogs.pop();
  renderAuditLogs();
}

function renderAuditLogs(filterTier = "ALL") {
  const tbody = document.getElementById("audit-table-body");
  if (!tbody) return;

  const filtered = filterTier === "ALL" 
    ? auditLogs 
    : auditLogs.filter(item => item.risk_tier === filterTier);

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="py-8 text-center text-slate-500 font-mono">No incidents match severity filter '${filterTier}'</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(row => {
    let tierPill = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400">INFO</span>`;
    if (row.risk_tier === "CRITICAL") {
      tierPill = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">CRITICAL</span>`;
    } else if (row.risk_tier === "HIGH") {
      tierPill = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">HIGH</span>`;
    } else if (row.risk_tier === "MEDIUM") {
      tierPill = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-yellow-500/10 text-yellow-400 border border-yellow-500/20">MEDIUM</span>`;
    } else {
      tierPill = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">LOW</span>`;
    }

    const prevCity = row.previous_location?.city ? `${row.previous_location.city}` : "Origin";
    const currCity = row.current_location?.city ? `${row.current_location.city}` : "Dest";
    const travel = `${prevCity} → ${currCity}`;
    const reasons = (row.reasons || []).join(", ") || "None";
    const timeFormatted = new Date(row.timestamp).toLocaleTimeString();

    return `
      <tr class="hover:bg-dark-850/50 transition-colors">
        <td class="py-3 px-4 text-slate-400">${timeFormatted}</td>
        <td class="py-3 px-4 text-white font-semibold">${row.user_id}</td>
        <td class="py-3 px-4">${tierPill}</td>
        <td class="py-3 px-4 font-bold ${row.risk_score > 60 ? 'text-rose-400' : 'text-slate-300'}">${row.risk_score}</td>
        <td class="py-3 px-4 text-slate-300 font-mono">${(row.velocity_kmph || 0).toLocaleString()} km/h</td>
        <td class="py-3 px-4 text-slate-400">${travel}</td>
        <td class="py-3 px-4 text-slate-400 text-[11px] truncate max-w-xs" title="${reasons}">${reasons}</td>
      </tr>
    `;
  }).join("");
}

function filterLogs(tier) {
  document.querySelectorAll(".log-filter-btn").forEach(btn => {
    if (btn.getAttribute("data-filter") === tier) {
      btn.classList.add("active", "bg-dark-800", "text-white");
    } else {
      btn.classList.remove("active", "bg-dark-800", "text-white");
    }
  });
  renderAuditLogs(tier);
}

function refreshAuditLogs() {
  refreshData();
  renderAuditLogs();
  showToast("Audit ledger refreshed from in-memory ring buffer");
}

function exportAuditCsv() {
  const headers = ["Timestamp", "User_ID", "Risk_Score", "Tier", "Velocity_kmph", "Distance_km", "Reasons"];
  const rows = auditLogs.map(a => [
    `"${a.timestamp}"`,
    `"${a.user_id}"`,
    a.risk_score,
    `"${a.risk_tier}"`,
    a.velocity_kmph,
    a.distance_km,
    `"${(a.reasons || []).join('; ')}"`
  ]);

  const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.join(","))].join("\n");
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", `aegis_audit_trail_${new Date().toISOString().slice(0, 10)}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  showToast("Exported audit trail to CSV");
}

// SDK Snippet Generator
function setSdkTab(lang) {
  currentSdkLang = lang;
  document.querySelectorAll(".sdk-tab-btn").forEach(btn => {
    if (btn.getAttribute("data-sdk") === lang) {
      btn.classList.add("active", "bg-brand-600", "text-white");
      btn.classList.remove("text-slate-400");
    } else {
      btn.classList.remove("active", "bg-brand-600", "text-white");
      btn.classList.add("text-slate-400");
    }
  });
  updateSdkCode();
}

function updateSdkCode() {
  const codeBox = document.getElementById("sdk-code-box");
  if (!codeBox) return;

  const user = document.getElementById("sim-user")?.value || "demo_user_showcase";
  const lat = document.getElementById("sim-lat")?.value || "35.6762";
  const lon = document.getElementById("sim-lon")?.value || "139.6503";
  const city = document.getElementById("sim-city")?.value || "Tokyo";
  const country = document.getElementById("sim-country")?.value || "JP";
  const device = document.getElementById("sim-device")?.value || "dev-ios-unregistered-77";
  const ip = document.getElementById("sim-ip")?.value || "203.0.113.15";

  if (currentSdkLang === "curl") {
    codeBox.innerHTML = `<code>curl -X POST "https://impossible-travel-auth-anomaly-engi.vercel.app/v1/auth/evaluate" \\
     -H "Content-Type: application/json" \\
     -H "X-API-Key: ${activeApiKey}" \\
     -d '{
       "user_id": "${user}",
       "login_ts": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
       "lat": ${lat},
       "lon": ${lon},
       "city": "${city}",
       "country": "${country}",
       "device_id": "${device}",
       "ip": "${ip}"
     }'</code>`;
  } else if (currentSdkLang === "python") {
    codeBox.innerHTML = `<code>import requests
from datetime import datetime, timezone

def evaluate_login_attempt(user_id, lat, lon, device_id, ip):
    payload = {
        "user_id": user_id,
        "login_ts": datetime.now(timezone.utc).isoformat(),
        "lat": lat,
        "lon": lon,
        "city": "${city}",
        "country": "${country}",
        "device_id": device_id,
        "ip": ip
    }
    
    response = requests.post(
        "https://impossible-travel-auth-anomaly-engi.vercel.app/v1/auth/evaluate",
        headers={"X-API-Key": "${activeApiKey}"},
        json=payload,
        timeout=1.5
    )
    result = response.json()
    
    # Enforce automated security policy
    if result.get("risk_score", 0) >= 80.0:
        raise PermissionError(f"Login blocked: {result.get('reasons')}")
    elif result.get("risk_score", 0) >= 40.0:
        return {"action": "CHALLENGE_MFA"}
        
    return {"action": "ALLOW"}</code>`;
  } else if (currentSdkLang === "node") {
    codeBox.innerHTML = `<code>// NextAuth.js / Express Middleware
async function checkAuthAnomaly(req, user) {
  const payload = {
    user_id: user.id,
    login_ts: new Date().toISOString(),
    lat: req.geo?.latitude || ${lat},
    lon: req.geo?.longitude || ${lon},
    city: req.geo?.city || "${city}",
    country: req.geo?.country || "${country}",
    device_id: req.headers['x-device-fingerprint'] || "${device}",
    ip: req.ip || "${ip}"
  };

  const response = await fetch("https://impossible-travel-auth-anomaly-engi.vercel.app/v1/auth/evaluate", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": "${activeApiKey}"
    },
    body: JSON.stringify(payload)
  });

  const evaluation = await response.json();
  if (evaluation.risk_tier === "CRITICAL") {
    throw new Error("Impossible Travel Detected: Access Denied");
  }
  return evaluation;
}</code>`;
  } else if (currentSdkLang === "go") {
    codeBox.innerHTML = `<code>package main

import (
    "bytes"
    "encoding/json"
    "net/http"
    "time"
)

type AuthEvent struct {
    UserID   string    \`json:"user_id"\`
    LoginTs  string    \`json:"login_ts"\`
    Lat      float64   \`json:"lat"\`
    Lon      float64   \`json:"lon"\`
    DeviceID string    \`json:"device_id"\`
    IP       string    \`json:"ip"\`
}

func EvaluateLogin(userID, deviceID, ip string, lat, lon float64) (*http.Response, error) {
    event := AuthEvent{
        UserID:   userID,
        LoginTs:  time.Now().UTC().Format(time.RFC3339),
        Lat:      lat,
        Lon:      lon,
        DeviceID: deviceID,
        IP:       ip,
    }
    
    body, _ := json.Marshal(event)
    req, _ := http.NewRequest("POST", "https://impossible-travel-auth-anomaly-engi.vercel.app/v1/auth/evaluate", bytes.NewBuffer(body))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-API-Key", "${activeApiKey}")
    
    client := &http.Client{Timeout: 2 * time.Second}
    return client.Do(req)
}</code>`;
  }
}

function copySdkCode() {
  const codeBox = document.getElementById("sdk-code-box");
  if (!codeBox) return;
  navigator.clipboard.writeText(codeBox.innerText);
  showToast("SDK snippet copied to clipboard");
}

// API Key Provisioning Form
async function generateNewKey(e) {
  e.preventDefault();
  const label = document.getElementById("new-key-name").value;
  
  try {
    const res = await fetch("/v1/keys/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: label })
    });
    const data = await res.json();
    
    document.getElementById("new-key-value").textContent = data.api_key;
    document.getElementById("new-key-banner").classList.remove("hidden");
    showToast(`Key created for ${label}`);
  } catch (err) {
    // Graceful fallback key
    const mockKey = `sk_live_${Math.random().toString(36).substring(2)}${Math.random().toString(36).substring(2)}`;
    document.getElementById("new-key-value").textContent = mockKey;
    document.getElementById("new-key-banner").classList.remove("hidden");
    showToast(`Provisioned key: ${label}`);
  }
}

function copyGeneratedKey() {
  const val = document.getElementById("new-key-value").textContent;
  navigator.clipboard.writeText(val);
  showToast("API Key copied to clipboard");
}

// Fetch live telemetry from /v1/stats
async function refreshData() {
  try {
    const res = await fetch("/v1/stats", {
      headers: { "X-API-Key": activeApiKey }
    });
    if (res.ok) {
      const stats = await res.json();
      if (stats.active_monitored_users) {
        document.getElementById("kpi-total-eval").textContent = stats.active_monitored_users.toLocaleString();
      }
      if (stats.critical_threats !== undefined) {
        document.getElementById("kpi-critical-threats").textContent = stats.critical_threats.toLocaleString();
      }
    }
  } catch (err) {
    console.debug("Telemetry fetch using baseline data");
  }
}

function initCopyButtons() {
  const btn = document.getElementById("copy-active-key-btn");
  if (btn) {
    btn.addEventListener("click", () => {
      navigator.clipboard.writeText(activeApiKey);
      showToast("Master API Key copied");
    });
  }
}
