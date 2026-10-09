// Alibi dashboard. Every number on the page comes from the API, which reads the real data
// snapshot (HIBP, CISA KEV, abuse.ch, Spamhaus, ransomware.live, iptoasn, OONI, TeleGeography,
// public-dns.info) or the live news feeds. Nothing here is generated.

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];
const fmt = (n) => Number(n).toLocaleString("en-US");
const compact = (n) => Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(n);
const pct = (x, d = 2) => `${(x * 100).toFixed(d)}%`;
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const day = (iso) => new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

function ago(iso) {
  if (!iso) return "";
  const mins = Math.round((Date.now() - new Date(iso)) / 60000);
  if (mins < 60) return `${Math.max(mins, 1)} min ago`;
  if (mins < 1440) return `${Math.round(mins / 60)} h ago`;
  return `${Math.round(mins / 1440)} days ago`;
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(`${res.status} ${(await res.text()).slice(0, 200)}`);
  return res.json();
}

const kpi = (v, l) => `<div class="kpi"><div class="v">${v}</div><div class="l">${l}</div></div>`;

function bars(el, rows, label = (n) => fmt(n)) {
  const max = Math.max(...rows.map((r) => r[1]), 1);
  el.innerHTML = rows.map(([k, n]) => `<div class="bar"><span>${esc(k)}</span>
    <div class="track"><div class="fill" style="width:${(n / max) * 100}%"></div></div><span class="n">${label(n)}</span></div>`).join("");
}

// ---------- tabs ----------
const loaders = {};
const loaded = new Set();

function show(hash) {
  // "#check/travel" opens a tab and, for the sign-in check, runs that story
  let [tab, story] = hash.split("/");
  if (!$(`#tab-${tab}`)) tab = "home";
  $$(".tab").forEach((s) => (s.hidden = s.id !== `tab-${tab}`));
  $$("nav a").forEach((a) => a.classList.toggle("on", a.dataset.tab === tab));
  if (!loaded.has(tab) && loaders[tab]) {
    loaded.add(tab);
    loaders[tab]().catch((err) => console.error(tab, err));
  }
  if (tab === "check" && tripMap) setTimeout(() => tripMap.invalidateSize(), 50);
  if (tab === "globe" && globe) setTimeout(sizeGlobe, 50);
  window.scrollTo(0, 0);
  if (tab === "check" && PRESETS[story]) applyPreset(story);
}
window.addEventListener("hashchange", () => show(location.hash.slice(1)));

// ---------- libraries, loaded only when a tab needs them ----------
const LIBS = {
  d3: "/static/vendor/d3.min.js",
  topojson: "/static/vendor/topojson-client.min.js",
  globe: "/static/vendor/globe.gl.min.js", // includes three.js, about 1.9 MB
  leaflet: "/static/vendor/leaflet.js",
};
const libLoads = {};
function need(...names) {
  return Promise.all(names.map((n) => (libLoads[n] ??= new Promise((ok, fail) => {
    const tag = document.createElement("script");
    tag.src = LIBS[n];
    tag.onload = ok;
    tag.onerror = () => fail(new Error(`Could not load ${n}`));
    document.head.append(tag);
  }))));
}

// ---------- shared country data ----------
const WORLD_URL = "/static/vendor/countries-110m.json"; // world-atlas 2.0.2, self-hosted
let worldPromise;

function center(f) {
  // centre of the country's largest piece of land (so France sits in Europe, not halfway to French Guiana)
  if (f.geometry.type === "Polygon") return d3.geoCentroid(f);
  const parts = f.geometry.coordinates.map((c) => ({ type: "Polygon", coordinates: c }));
  return d3.geoCentroid(parts.reduce((a, b) => (d3.geoArea(a) > d3.geoArea(b) ? a : b)));
}

function world() {
  worldPromise ??= Promise.all([fetch(WORLD_URL).then((r) => r.json()), api("/v1/intel/countries"), need("d3", "topojson")]).then(([topo, data]) => {
    const byNumeric = {};
    for (const [a2, c] of Object.entries(data.countries)) byNumeric[+c.numeric] = { a2, ...c };
    const features = topojson.feature(topo, topo.objects.countries).features.filter((f) => f.id !== "010"); // no Antarctica
    const centers = {};
    features.forEach((f) => {
      f.properties.c = byNumeric[+f.id];
      if (f.properties.c) centers[f.properties.c.a2] = center(f);
    });
    return { features, data, centers, topo };
  });
  return worldPromise;
}

const sampleCache = {};
const samples = (cc) => (sampleCache[cc] ??= api(`/v1/intel/sample-ips?country=${cc}`));

// ---------- home ----------
loaders.home = async () => {
  const o = await api("/v1/intel/overview");
  const t = o.takeovers_caught, rw = o.ransomware_victims;
  $("#home-kpis").innerHTML = [
    kpi(compact(o.accounts_exposed_last_12_months), `accounts exposed in ${o.breaches_last_12_months} published breaches in the last 12 months`),
    kpi(fmt(o.malicious_ips), "servers caught spreading malware or running botnets right now"),
    kpi(fmt(rw.victims), `businesses claimed by ransomware gangs, ${day(rw.from)} to ${day(rw.to)}`),
    kpi(fmt(o.exploited_flaws_last_30_days), "software flaws newly confirmed as exploited in the last 30 days"),
    kpi(fmt(o.criminal_networks), "whole networks Spamhaus lists as run by criminals"),
    kpi(`${t.caught} of ${t.of}`, `account takeovers caught in the test data, asking only ${pct(t.challenge_rate)} of sign-ins for a code`),
    kpi(compact(o.total_accounts_exposed), `accounts exposed across ${fmt(o.total_breaches)} breaches on record`),
    kpi(fmt(o.countries_with_confirmed_blocking), "countries where websites were found blocked in the last 30 days"),
  ].join("");
  $("#home-asof").textContent = `Breach, flaw, malware, ransomware and network data as of ${day(o.as_of)}. News is fetched live.`;
};

// ---------- live globe ----------
const METRICS = {
  malicious_ips: {
    unit: "malware servers",
    state: "m",
    title: "Malware and botnet servers right now",
    explain: "Servers that security researchers caught spreading malware or controlling botnets in the last few days. Most are not rented servers but hacked home routers, cameras and other devices, which is why countries with huge numbers of home connections lead this list.",
    source: "malware",
  },
  ransomware_victims: {
    unit: "ransomware victims this week",
    title: "Ransomware victims this week",
    explain: "Businesses that ransomware gangs posted on their leak sites this week, by the victim's country. Gangs post victims who refuse to pay, so the real number of attacks is higher.",
    source: "ransomware",
  },
  confirmed_blocks: {
    unit: "websites confirmed blocked",
    title: "Websites confirmed blocked, last 30 days",
    explain: "Volunteers running OONI Probe test whether websites and apps load. A confirmed block means the test hit a known government or ISP block page. More volunteers means more tests, so a high number means heavy blocking or a lot of testing, and often both.",
    source: "censorship",
  },
  hosting_ipv4: {
    unit: "hosting / VPN addresses",
    title: "Addresses on hosting / VPN networks",
    explain: "IPv4 addresses that belong to cloud, hosting and VPN companies. Real customers rarely sign in from a data center, but bots, scrapers and people hiding behind VPNs do, so Alibi treats these networks with extra care.",
    source: "network",
  },
  dns_resolvers: {
    unit: "public DNS servers",
    state: "d",
    title: "Working public DNS servers",
    explain: "DNS servers turn names like google.com into addresses. Open public ones are useful, but attackers also misuse them to flood websites with traffic, and governments block them to enforce censorship.",
    source: "dns",
  },
  cable_landings: {
    unit: "undersea cable landing stations",
    title: "Undersea cable landing stations",
    explain: "Where undersea internet cables come ashore. Almost all traffic between continents runs through these cables, so countries with few landings can be cut off by a single fault or attack.",
    source: "cables",
  },
  tor_exits: {
    unit: "Tor exits",
    title: "Tor exit relays",
    explain: "Tor hides where a person really is by bouncing their traffic around the world. Exit relays are where that traffic comes back out, so a sign-in from one could be anyone, anywhere.",
    source: "tor",
  },
};
let metric = "malicious_ips", globe, selected, journey = [], journeyArcs = [];

function sizeGlobe() {
  const el = $("#globe");
  globe.width(el.clientWidth).height(el.clientHeight);
}

const IMG = "/static/vendor/img/"; // NASA Blue Marble imagery (public domain), self-hosted
// Phones and tablets get 2048-pixel textures; desktops keep the full 4096.
const SMALL_SCREEN = matchMedia("(pointer: coarse)").matches || innerWidth < 900;
const TEX_W = SMALL_SCREEN ? 2048 : 4096;
const REDUCED_MOTION = matchMedia("(prefers-reduced-motion: reduce)").matches;
let places = [], pickData = null, pickW = 0, pickH = 0, heatPromise, cablesLoaded = null, selState = null, snapshotAt = "";

// The server paints each metric's states into the Earth texture (see intel/globe.py), so the browser
// downloads one image instead of drawing 4,596 states itself.
const texUrl = (m) => `/v1/intel/globe/${m}.jpg?w=${TEX_W}&v=${encodeURIComponent(snapshotAt)}`;

async function loadPickMap() {
  const [img, rows] = await Promise.all([
    new Promise((ok, fail) => { const i = new Image(); i.onload = () => ok(i); i.onerror = fail; i.src = "/v1/intel/globe/pick.png"; }),
    api("/v1/intel/globe/places"),
  ]);
  const c = document.createElement("canvas");
  c.width = pickW = img.width;
  c.height = pickH = img.height;
  const ctx = c.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(img, 0, 0);
  pickData = ctx.getImageData(0, 0, pickW, pickH).data;
  places = rows.rows.map(([n, c2, t, m, d, ip], i) => ({ i, n, c: c2, t, m, d, ip }));
}

function stateAt(at) {
  if (!at || !pickData) return null;
  const x = Math.min(pickW - 1, Math.floor(((at.lng + 180) / 360) * pickW));
  const y = Math.min(pickH - 1, Math.floor(((90 - at.lat) / 180) * pickH));
  const k = (y * pickW + x) * 4;
  const index = ((pickData[k] << 8) | pickData[k + 1]) - 1;
  return index >= 0 ? places[index] : null;
}

const perMillion = (count, ip) => (ip >= 100000 ? `${(count / ip * 1e6).toFixed(2)} per million addresses` : "too few addresses to rate");

loaders.globe = async () => {
  const el = $("#globe");
  // poster: the flat map of the same data while three.js loads
  el.innerHTML = `<div class="globe-poster"><img alt="" src="${texUrl(metric)}"><span>Loading the 3D globe…</span></div>`;
  const [{ features, data, centers }] = await Promise.all([world(), need("globe"), loadPickMap()]);
  snapshotAt = data.as_of;
  if (!data.totals.tor_exit_relays) $('[data-metric="tor_exits"]').remove(); // Tor list unreachable when the snapshot was built
  globe = Globe({ animateIn: !REDUCED_MOTION, rendererConfig: { antialias: !SMALL_SCREEN, powerPreference: "high-performance" } })(el)
    .globeImageUrl(texUrl(metric))
    .showAtmosphere(true).atmosphereColor("#9ec9ff").atmosphereAltitude(0.16)
    .onGlobeReady(() => $(".globe-poster")?.remove())
    .onGlobeClick((at) => pickAt(features, at))
    .polygonsData([]).polygonCapColor(() => "rgba(255,255,255,0.18)").polygonSideColor(() => "rgba(0,0,0,0)")
    .polygonStrokeColor(() => "#ffffff").polygonAltitude(0.006)
    .onPolygonClick((_p, _e, at) => pickAt(features, at))
    .pathPoints("coords").pathPointLat((p) => p[0]).pathPointLng((p) => p[1]).pathPointAlt(0.004)
    .pathColor((p) => p.color).pathDashLength(0.08).pathDashGap(0.01).pathDashAnimateTime(16000).pathTransitionDuration(0)
    .pathLabel((p) => `<div class="globe-tip">Undersea cable: ${esc(p.name)}</div>`)
    .onPathClick((_p, _e, at) => pickAt(features, at))
    .pointLat("lat").pointLng("lng").pointAltitude(0.005).pointRadius(0.12).pointColor(() => "#ffd27a").pointsMerge(true)
    .arcsData([]).arcColor("color").arcStroke(0.8).arcDashLength(0.5).arcDashGap(0.15).arcDashAnimateTime(1600)
    .arcAltitudeAutoScale(0.45).arcLabel((a) => `<div class="globe-tip">${esc(a.label)}</div>`)
    .labelsData([]).labelLat("lat").labelLng("lng").labelText("text").labelSize(1.1).labelDotRadius(0.45)
    .labelColor(() => "#ffffff").labelResolution(2);
  if (!SMALL_SCREEN) globe.bumpImageUrl(`${IMG}earth-topology.png`).backgroundImageUrl(`${IMG}night-sky.png`);
  globe.renderer().setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
  globe.pointOfView({ lat: 22, lng: 40, altitude: SMALL_SCREEN ? 2.4 : 2 });
  Object.assign(globe.controls(), { autoRotate: !REDUCED_MOTION && !SMALL_SCREEN, autoRotateSpeed: 0.35, minDistance: 112, maxDistance: 520 });
  $("#reset-view").addEventListener("click", () => globe.pointOfView({ lat: 22, lng: 40, altitude: 2 }, 800));
  el.addEventListener("pointerdown", () => (globe.controls().autoRotate = false), { once: true });
  sizeGlobe();
  window.addEventListener("resize", sizeGlobe);
  // stop drawing frames while the globe is scrolled out of view
  new IntersectionObserver(([e]) => (e.isIntersecting ? globe.resumeAnimation() : globe.pauseAnimation())).observe(el);
  globe.__centers = centers;
  globe.__data = data;
  globe.__features = features;

  // hover: which state is under the mouse, read from the pick image (no 3D objects, no lag)
  const tip = $("#globe-tip");
  let frame = 0;
  el.addEventListener("mousemove", (e) => {
    if (frame) return;
    frame = requestAnimationFrame(() => {
      frame = 0;
      const box = el.getBoundingClientRect();
      const s = stateAt(globe.toGlobeCoords(e.clientX - box.left, e.clientY - box.top));
      if (!s) return void (tip.hidden = true);
      tip.hidden = false;
      tip.style.left = `${Math.min(e.clientX - box.left + 14, box.width - 260)}px`;
      tip.style.top = `${e.clientY - box.top + 14}px`;
      tip.innerHTML = stateTip(s);
    });
  });
  el.addEventListener("mouseleave", () => (tip.hidden = true));

  $$("[data-metric]").forEach((b) => b.addEventListener("click", () => {
    metric = b.dataset.metric;
    $$("[data-metric]").forEach((x) => x.classList.toggle("on", x === b));
    paint();
    if (selected) selectCountry(selected, globe.__lastAt);
  }));
  $("#show-cables").addEventListener("change", async () => {
    const on = $("#show-cables").checked;
    if (on) cablesLoaded ??= api("/v1/intel/cables"); // the 733 cable paths load only when asked for
    const cab = on ? await cablesLoaded : null;
    globe.pathsData(on ? cab.cables.flatMap((c) => c.paths.map((p) => ({ name: c.name, color: c.color, coords: p }))) : [])
      .pointsData(on ? cab.landings : []);
  });
  $$("[data-journey]").forEach((b) => b.addEventListener("click", () => {
    journey = b.dataset.journey.split(",");
    renderJourney();
    runJourney();
  }));
  $("#journey-go").addEventListener("click", runJourney);
  paint();
};

function pickAt(features, at) {
  const f = at && features.find((x) => d3.geoContains(x, [at.lng, at.lat]));
  if (f) selectCountry(f, at);
}

function stateTip(s) {
  const c = globe.__data.countries[s.c];
  const m = METRICS[metric];
  const rate = m.state ? `<br>${perMillion(m.state === "m" ? s.m : s.d, s.ip)}` : "";
  return `<b>${esc(s.n)}</b> <span class="muted">${esc(s.t)}${c ? `, ${esc(c.name)}` : ""}</span>
    <br>${fmt(s.m)} malware servers · ${fmt(s.d)} public DNS servers here${rate}` +
    (c && !m.state ? `<br>${esc(c.name)} (country-level data): ${fmt(c[metric])} ${esc(m.unit)}` : "");
}

async function paint() {
  const data = globe.__data;
  const m = METRICS[metric];
  globe.globeImageUrl(texUrl(metric));
  const lg = await api(`/v1/intel/globe/${metric}/legend`);
  $("#legend").innerHTML = `<b>${esc(lg.unit)}</b>${lg.level === "country" ? " · country-level" : ""}<div class="bins">` +
    [...lg.bins, lg.no_data].map((b) => `<span><i style="background:${b.color}"></i>${esc(b.label)}</span>`).join("") + "</div>";
  $("#top-title").textContent = `Top 10 ${lg.level === "state" ? "states and provinces" : "countries"}: ${m.title.toLowerCase()}`;
  $("#top-list").innerHTML = lg.top.map((t) => `<li><span>${esc(t.name)}</span><b>${fmt(t.value)}${
    t.count !== undefined ? ` <span class="muted">(${fmt(t.count)})</span>` : ""}</b></li>`).join("");
  $("#metric-explain").textContent = m.explain;
  const s = data.sources[m.source];
  const how = lg.level === "state"
    ? ` Each server is placed in its state by IP geolocation (IP Geolocation by <a href="https://db-ip.com" target="_blank" rel="noopener">DB-IP</a>, CC BY 4.0), then divided by the IPv4 addresses DB-IP places in that state. States with fewer than ${fmt(lg.min_addresses)} addresses are grey.`
    : " This number is only known per country, so every state in a country shares its colour.";
  $("#map-sources").innerHTML = s ? `Source: <a href="${s.url}" target="_blank" rel="noopener">${esc(s.name)}</a> (${esc(s.license)}).${how} Colours are ColorBrewer YlOrRd (colour-blind safe). Data as of ${day(lg.as_of)}.` : "";
}

async function highlightState(s) {
  if (!s) return globe.polygonsData([]);
  const { rings } = await api(`/v1/intel/globe/state/${s.i}`);
  globe.polygonsData([{ type: "Feature", properties: {}, geometry: { type: "MultiPolygon",
    coordinates: rings.map((r) => [r.map(([lat, lng]) => [lng, lat])]) } }]);
}

async function selectCountry(f, at) {
  const c = f.properties.c;
  if (!c) return;
  selected = f;
  globe.__lastAt = at;
  const st = stateAt(at);
  selState = st && st.c === c.a2 ? st : null;
  highlightState(selState);
  const [lng, lat] = globe.__centers[c.a2];
  globe.controls().autoRotate = false;
  globe.pointOfView(at ? { lat: at.lat, lng: at.lng, altitude: 1.2 } : { lat, lng, altitude: 1.5 }, 900);
  const facts = [
    ["Malware servers now", fmt(c.malicious_ips)],
    ["Ransomware victims this week", fmt(c.ransomware_victims)],
    ["Websites confirmed blocked", `${fmt(c.confirmed_blocks)} in ${compact(c.censorship_measurements)} tests`],
    ["Public DNS servers", fmt(c.dns_resolvers)],
    ["Hosting / VPN addresses", compact(c.hosting_ipv4)],
    ["Undersea cable landings", fmt(c.cable_landings)],
  ];
  if (globe.__data.totals.tor_exit_relays) facts.push(["Tor exits", fmt(c.tor_exits)]);
  const key = METRICS[metric].state === "d" ? "d" : "m";
  const label = key === "d" ? "public DNS servers" : "malware servers";
  const topStates = places.filter((s) => s.c === c.a2 && s[key] > 0).sort((a, b) => b[key] - a[key]).slice(0, 6);
  heatPromise ??= api("/v1/intel/heat"); // city lists load only when a country is opened
  const spots = (await heatPromise).places?.[c.a2]?.[key === "d" ? "dns" : "malware"] || [];
  $("#country-panel").innerHTML = `${selState ? `<div class="place"><b>${esc(selState.t)}: ${esc(selState.n)}</b><br>
      ${fmt(selState.m)} malware servers · ${fmt(selState.d)} public DNS servers located here
      <br><span class="muted">${perMillion(selState[key], selState.ip)} (${label})</span></div>` : ""}
    <h3>${esc(c.name)}</h3>
    <p class="fineprint">The boxes below are country-level totals.</p>
    <div class="facts">${facts.map(([k, v]) => `<div><b>${k}</b>${v}</div>`).join("")}</div>
    ${topStates.length ? `<p class="fineprint"><b>States with the most ${label}:</b> ${topStates.map((s) => `${esc(s.n)} (${fmt(s[key])})`).join(" · ")}</p>` : ""}
    ${spots.length ? `<p class="fineprint"><b>Top cities:</b> ${spots.slice(0, 6).map(([city, n]) => `${esc(city)} (${fmt(n)})`).join(" · ")}</p>` : ""}
    <p class="fineprint" id="country-nets">Looking up its networks…</p>
    <button class="btn" id="add-journey" ${journey.length >= 3 ? "disabled" : ""}>Add to journey</button>`;
  $("#add-journey").addEventListener("click", () => {
    if (journey.length < 3 && journey.at(-1) !== c.a2) journey.push(c.a2);
    renderJourney();
    $("#add-journey").disabled = journey.length >= 3;
  });
  try {
    const s = await samples(c.a2);
    const homes = s.home.map((h) => esc(h.network)).join(" and ");
    $("#country-nets").innerHTML = (homes ? `Biggest home and business networks: ${homes}.` : "No home networks on record.") +
      (s.malware ? ` A server reported for malware here: ${esc(s.malware)}.` : "");
  } catch {
    $("#country-nets").textContent = "";
  }
}

function renderJourney() {
  const names = globe.__data.countries;
  $("#journey-list").innerHTML = journey.map((cc, i) => `<li>${esc(names[cc].name)}${i === 0 ? " <span class='muted'>(usual home)</span>" : ""}
    <button data-drop="${i}" aria-label="Remove">remove</button></li>`).join("");
  $$("[data-drop]").forEach((b) => b.addEventListener("click", () => {
    journey.splice(+b.dataset.drop, 1);
    renderJourney();
  }));
  $("#journey-go").disabled = journey.length < 2;
  const pts = journey.map((cc) => ({ lat: globe.__centers[cc][1], lng: globe.__centers[cc][0], text: names[cc].name }));
  globe.labelsData(pts);
  journeyArcs = pts.slice(1).map((p, i) => ({ startLat: pts[i].lat, startLng: pts[i].lng, endLat: p.lat, endLng: p.lng,
    color: [css("--accent"), css("--accent")], label: `${pts[i].text} → ${p.text}` }));
  globe.arcsData(journeyArcs);
  $("#journey-result").innerHTML = "";
}

async function runJourney() {
  if (journey.length < 2) return;
  const names = globe.__data.countries, centers = globe.__centers;
  const gap = Math.max(1, +$("#journey-minutes").value || 1);
  const btn = $("#journey-go");
  $("#journey-err").textContent = "";
  btn.disabled = true;
  btn.textContent = "Checking…";
  try {
    const hops = await Promise.all(journey.map(samples));
    if (hops.some((h) => !h.home.length)) throw new Error("One of these countries has no home networks on record to sign in from.");
    const ev = (ts, i) => {
      const [lon, lat] = centers[journey[i]];
      return { user_id: "demo", login_ts: new Date(ts).toISOString(), ip: hops[i].home[0].ip, country: journey[i],
        city: names[journey[i]].name, lat, lon, success: true, device_id: "usual-laptop", browser: "Chrome 128.0",
        os: "Windows 10", device_type: "desktop" };
    };
    const t0 = Date.now() - gap * 60000 * (journey.length - 1);
    const events = [];
    for (let i = 6; i >= 0; i--) events.push(ev(t0 - i * 2 * 86400000, 0));
    for (let i = 1; i < journey.length; i++) events.push(ev(t0 + i * gap * 60000, i));
    const { timeline } = await api("/v1/demo/check", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ events }),
    });
    const steps = timeline.slice(-(journey.length - 1));
    const tierColor = { LOW: css("--ok"), MEDIUM: css("--warn"), HIGH: css("--risk"), CRITICAL: css("--risk") };
    journeyArcs.forEach((a, i) => {
      a.color = [tierColor[steps[i].tier], tierColor[steps[i].tier]];
      a.label = `${a.label}: ${fmt(Math.round(steps[i].distance_km))} km in ${gap} min, ${steps[i].tier}`;
    });
    globe.arcsData([...journeyArcs]);
    $("#journey-result").innerHTML = steps.map((s, i) => `<div class="hop ${s.tier}"><b>${esc(names[journey[i]].name)} → ${esc(names[journey[i + 1]].name)}</b>:
      ${fmt(Math.round(s.distance_km))} km in ${gap} min${s.velocity_kmph ? ` (${fmt(Math.round(s.velocity_kmph))} km/h)` : ""}.
      <span class="badge ${s.tier}">${s.tier}</span><br><span class="muted">${esc(s.reasons[0])}</span></div>`).join("") +
      `<p class="fineprint">Each hop signs in from that country's biggest home network, after two weeks of usual sign-ins from ${esc(names[journey[0]].name)}. Planes fly about 900 km/h.</p>`;
  } catch (err) {
    $("#journey-err").textContent = err.message;
  } finally {
    btn.disabled = journey.length < 2;
    btn.textContent = "Check this journey";
  }
}

// ---------- breaches ----------
let allBreaches, breachList = [];
const HOW_SHORT = (h) => h.replace("Hacked, method not disclosed", "Hacked (method not given)");

function breachRows(rows) {
  breachList = rows;
  $("#breach-rows").innerHTML = rows.map((b, i) => `<tr class="click" data-i="${i}"><td><b>${esc(b.name)}</b><br><span class="fineprint">${esc(b.domain || "")}</span></td>
    <td>${day(b.breach_date)}</td><td class="num">${fmt(b.accounts)}</td><td>${esc(HOW_SHORT(b.how))}</td></tr>`).join("")
    || `<tr><td colspan="4" class="muted">No published breach matches. That's good news, not a guarantee.</td></tr>`;
}

$("#breach-rows").addEventListener("click", (e) => {
  const tr = e.target.closest("tr.click");
  if (!tr) return;
  if (tr.nextElementSibling?.classList.contains("detail")) return tr.nextElementSibling.remove();
  const b = breachList[+tr.dataset.i];
  tr.insertAdjacentHTML("afterend", `<tr class="detail"><td colspan="4">${esc(b.summary)}<br><br><b>Exposed:</b> ${esc(b.data.join(", "))}
    <br><span class="fineprint">Write-up: Have I Been Pwned, CC BY 4.0.</span></td></tr>`);
});

loaders.breaches = async () => {
  const s = await api("/v1/intel/breaches");
  const top = s.biggest_companies[0];
  $("#breach-kpis").innerHTML = [
    kpi(fmt(s.total_breaches), "breaches on record"),
    kpi(compact(s.total_accounts), "accounts exposed in total"),
    kpi(fmt(s.last_12_months.breaches), `breaches in the last 12 months, ${compact(s.last_12_months.accounts)} accounts`),
    kpi(compact(top.accounts), `biggest single company breach: ${esc(top.name)}`),
    kpi(compact(s.lists.accounts), `accounts in ${s.lists.count} lists traded by hackers and harvested by info-stealer malware`),
  ].join("");
  bars($("#breach-how"), s.how_stolen.map(([h, n]) => [HOW_SHORT(h), n]));
  bars($("#breach-data"), s.most_exposed_data, (n) => `${fmt(n)} breaches`);
  bars($("#breach-years"), Object.entries(s.accounts_by_year), compact);
  breachRows(s.biggest_companies);
};

$("#breach-search").addEventListener("input", async (e) => {
  const q = e.target.value.trim().toLowerCase();
  allBreaches ??= (await api("/v1/intel/breaches?full=true")).breaches;
  $("#breach-table-title").textContent = q ? `Breaches matching "${e.target.value.trim()}"` : "Biggest company breaches";
  const rows = q ? allBreaches.filter((b) => b.name.toLowerCase().includes(q) || (b.domain || "").toLowerCase().includes(q))
    : allBreaches.filter((b) => b.kind === "company").sort((a, b) => b.accounts - a.accounts);
  breachRows(rows.slice(0, 25));
});

// ---------- attacks ----------
loaders.attacks = async () => {
  const [t, { data }] = await Promise.all([api("/v1/intel/threats"), world()]);
  const name = (cc) => data.countries[cc]?.name || cc;
  const rw = t.ransomware;
  $("#attack-kpis").innerHTML = [
    kpi(fmt(t.malicious_ips), "servers caught spreading malware or running botnets"),
    kpi(fmt(t.threatfox_iocs_48h), "new threat indicators shared by researchers in the last 48 hours"),
    kpi(fmt(t.urlhaus_online), `malware download links still live, of ${fmt(t.urlhaus_urls_30d)} reported in 30 days`),
    kpi(fmt(rw.victims), `businesses claimed by ransomware gangs, ${day(rw.from)} to ${day(rw.to)}`),
    kpi(fmt(t.spamhaus_asn_drop), "whole networks run by criminals (Spamhaus)"),
  ].join("");
  const iot = t.iot_botnet_ips / t.malicious_ips;
  $("#attack-insight").innerHTML = `<b>The surprise:</b> only ${pct(t.hosting_share_of_malicious_ips, 0)} of these malware servers run on
    hosting or VPN networks, about the same as those networks' ${pct(t.hosting_share_of_internet, 0)} share of the internet.
    ${pct(iot, 0)} are home routers, cameras and other gadgets taken over by botnets like Mozi and Mirai.
    Blocking data centers alone would miss most of them, which is why Alibi checks every IP against these lists too.`;
  bars($("#attack-malware"), t.top_malware.filter(([m]) => !/^(unnamed|unknown malware|none)$/i.test(m)).slice(0, 10));
  bars($("#attack-countries"), t.top_countries.slice(0, 10).map(([cc, n]) => [name(cc), n]));
  $("#attack-networks").innerHTML = t.top_networks.map((n) => `<tr><td>${esc(n.network)} <span class="fineprint">AS${n.asn}</span></td>
    <td>${n.criminal_network ? '<span class="tag">criminal network</span>' : n.hosting ? "hosting / cloud" : "home or business internet provider"}</td>
    <td class="num">${fmt(n.count)}</td></tr>`).join("");
  $("#ransom-window").textContent = `${rw.victims} businesses posted on ransomware gangs' leak sites between ${day(rw.from)} and ${day(rw.to)}. ` +
    "Only totals are shown here: no victim names, links or stolen files.";
  bars($("#ransom-sectors"), rw.by_sector.filter(([s]) => !/not (found|stated)/i.test(s)).slice(0, 10));
  bars($("#ransom-countries"), rw.by_country.slice(0, 10).map(([cc, n]) => [name(cc), n]));
  bars($("#ransom-groups"), rw.by_group.slice(0, 10));
  $("#drop-text").textContent = `${fmt(t.spamhaus_drop_ranges)} address blocks (${compact(t.spamhaus_drop_addresses)} addresses) and ` +
    `${t.spamhaus_asn_drop} whole networks are on Spamhaus's "do not route" lists: hijacked, or run by spammers and cybercriminals. Where those networks are registered:`;
  bars($("#drop-countries"), t.spamhaus_asn_drop_countries.map(([cc, n]) => [name(cc), n]));
  $("#attack-sources").innerHTML = "Sources: " + Object.values(t.sources).map((s) =>
    `<a href="${s.url}" target="_blank" rel="noopener">${esc(s.name)}</a> (${esc(s.license)})`).join(" · ") + `. As of ${day(t.as_of)}.`;
};

// ---------- exploited flaws ----------
loaders.flaws = async () => {
  const f = await api("/v1/intel/flaws");
  $("#flaw-kpis").innerHTML = [
    kpi(fmt(f.added_last_7_days), "added in the last 7 days"),
    kpi(fmt(f.added_last_30_days), "added in the last 30 days"),
    kpi(fmt(f.total), "exploited flaws on the list"),
    kpi(fmt(f.ransomware_linked), "used in ransomware attacks"),
  ].join("");
  bars($("#flaw-vendors"), f.top_vendors_last_12_months);
  const thisMonth = f.as_of.slice(0, 7); // the snapshot's month is not over yet
  bars($("#flaw-months"), Object.entries(f.added_by_month).map(([m, n]) => [
    new Date(`${m}-01`).toLocaleDateString("en-GB", { month: "short", year: "numeric" }) + (m === thisMonth ? ", to date" : ""), n]));
  $("#flaw-rows").innerHTML = f.latest.map((r) => `<tr><td>${day(r.added)}</td>
    <td><a href="https://nvd.nist.gov/vuln/detail/${esc(r.cve)}" target="_blank" rel="noopener">${esc(r.cve)}</a><br>${esc(r.name)}</td>
    <td>${esc(r.vendor)} ${esc(r.product)}</td><td>${r.ransomware ? '<span class="tag">yes</span>' : "not known"}</td></tr>`).join("");
};

// ---------- account takeover: check a sign-in ----------
// Main business city of each country in the picker (for the map and the travel-speed check).
const CITIES = {
  IN: ["Mumbai", 19.076, 72.8777], US: ["New York", 40.7128, -74.006], GB: ["London", 51.5074, -0.1278],
  DE: ["Berlin", 52.52, 13.405], FR: ["Paris", 48.8566, 2.3522], NL: ["Amsterdam", 52.3676, 4.9041],
  BR: ["São Paulo", -23.5505, -46.6333], JP: ["Tokyo", 35.6762, 139.6503], SG: ["Singapore", 1.3521, 103.8198],
  AE: ["Dubai", 25.2048, 55.2708], AU: ["Sydney", -33.8688, 151.2093], CA: ["Toronto", 43.6532, -79.3832],
  NG: ["Lagos", 6.5244, 3.3792], ZA: ["Johannesburg", -26.2041, 28.0473], RU: ["Moscow", 55.7558, 37.6173],
  CN: ["Shanghai", 31.2304, 121.4737], KR: ["Seoul", 37.5665, 126.978], ID: ["Jakarta", -6.2088, 106.8456],
};
const DEVICES = {
  same: { device_id: "usual-laptop", browser: "Chrome 128.0", os: "Windows 10", device_type: "desktop" },
  new: { device_id: "unknown-phone", browser: "Chrome Mobile 128.0", os: "Android 14", device_type: "mobile" },
};
const PRESETS = {
  usual: { home: "IN", country: "IN", net: "home", device: "same", minutes: 900, fails: 0, correct: true },
  tor: { home: "IN", country: "IN", net: "tor", device: "same", minutes: 600, fails: 0, correct: true },
  vpn: { home: "IN", country: "IN", net: "vpn", device: "same", minutes: 600, fails: 0, correct: true },
  malware: { home: "IN", country: "IN", net: "malware", device: "same", minutes: 600, fails: 0, correct: true },
  abroad: { home: "IN", country: "BR", net: "newhome", device: "new", minutes: 2880, fails: 0, correct: true },
  travel: { home: "IN", country: "GB", net: "newhome", device: "same", minutes: 10, fails: 0, correct: true },
  guessing: { home: "IN", country: "IN", net: "newhome", device: "new", minutes: 600, fails: 6, correct: true },
};
// risk bar colour per tier: green, amber, orange, red
const TIER_COLOR = { LOW: "#2f7a4f", MEDIUM: "#d4a017", HIGH: "#e8710a", CRITICAL: "#b42318" };
const SAY = {
  LOW: "Looks like the real owner. Let them in.",
  MEDIUM: "A little unusual, but believable. Let them in and keep a note.",
  HIGH: "This story doesn't add up. Ask for a one-time code first.",
  CRITICAL: "Very likely not the owner. Block it and alert them.",
};

let tripMap, tripLayer, checkReady;
const ensureCheck = () => (checkReady ??= setupCheck());
loaders.check = ensureCheck;

async function setupCheck() {
  const [{ data }] = await Promise.all([world(), need("leaflet")]);
  const names = data.countries;
  const opts = Object.keys(CITIES)
    .sort((a, b) => names[a].name.localeCompare(names[b].name))
    .map((cc) => `<option value="${cc}">${esc(names[cc].name)} (${CITIES[cc][0]})</option>`).join("");
  $("#f-home").innerHTML = opts;
  $("#f-country").innerHTML = opts;
  tripMap = L.map("trip-map", { scrollWheelZoom: false, worldCopyJump: true }).setView([30, 40], 2);
  L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
    maxZoom: 6, attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
  }).addTo(tripMap);
  tripLayer = L.layerGroup().addTo(tripMap);
  applyPreset("usual", false);
}

async function applyPreset(name, run = true) {
  if (run) await ensureCheck();
  const p = PRESETS[name];
  $("#f-home").value = p.home;
  $("#f-country").value = p.country;
  $("#f-net").value = p.net;
  $("#f-device").value = p.device;
  $("#f-minutes").value = p.minutes;
  $("#f-fails").value = p.fails;
  $("#f-correct").checked = p.correct;
  $$("[data-preset]").forEach((b) => b.classList.toggle("on", b.dataset.preset === name));
  if (run) runCheck();
}
$$("[data-preset]").forEach((b) => b.addEventListener("click", () => applyPreset(b.dataset.preset)));
$("#check-form").addEventListener("submit", (e) => {
  e.preventDefault();
  $$("[data-preset]").forEach((b) => b.classList.remove("on"));
  runCheck();
});

function loginEvent(ts, ip, cc, device, success) {
  const [city, lat, lon] = CITIES[cc];
  return { user_id: "demo", login_ts: new Date(ts).toISOString(), ip, country: cc, city, lat, lon, success, ...DEVICES[device] };
}

async function runCheck() {
  await ensureCheck();
  const home = $("#f-home").value, there = $("#f-country").value, net = $("#f-net").value, device = $("#f-device").value;
  const minutes = Math.max(1, +$("#f-minutes").value || 1), fails = Math.min(10, Math.max(0, +$("#f-fails").value || 0));
  const btn = $("#f-go");
  $("#f-err").textContent = "";
  btn.disabled = true;
  btn.textContent = "Checking…";
  try {
    const [hs, ts] = await Promise.all([samples(home), samples(there)]);
    const usual = hs.home[0];
    let ip;
    if (net === "home") ip = home === there ? usual : ts.home[0];
    else if (net === "newhome") ip = home === there ? ts.home[1] || ts.home[0] : ts.home[0];
    else if (net === "vpn") ip = ts.hosting[0];
    else if (net === "malware") ip = { ip: ts.malware, network: "reported malware server" };
    else if (ts.tor) ip = { ip: ts.tor, network: "Tor" };
    else throw new Error("This server can't reach the Tor Project's exit list right now (torproject.org is blocked on some networks), so the Tor story can't be checked here.");

    // Two weeks of ordinary sign-ins from home, then the one being tested.
    const testAt = Date.now();
    const lastUsual = testAt - minutes * 60000;
    const events = [];
    for (let i = 6; i >= 0; i--) events.push(loginEvent(lastUsual - i * 2 * 86400000, usual.ip, home, "same", true));
    for (let i = fails; i >= 1; i--) events.push(loginEvent(testAt - i * 20000, ip.ip, there, device, false));
    events.push(loginEvent(testAt, ip.ip, there, device, $("#f-correct").checked));

    const { verdict } = await api("/v1/demo/check", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ events }),
    });
    renderVerdict(verdict, usual, ip, home, there, fails);
  } catch (err) {
    $("#f-err").textContent = err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = "Check this sign-in";
  }
}

// HIGH without impossible travel means the pattern is unusual for this account, not that the trip can't happen
const say = (v) => (v.risk_tier === "HIGH" && !v.reasons.some((r) => r.startsWith("Impossible travel"))
  ? "Unusual for this user. Ask for a one-time code first." : SAY[v.risk_tier]);

function renderVerdict(v, usual, ip, home, there, fails) {
  const n = v.network || {};
  const reasons = v.reasons.length ? v.reasons : ["Nothing unusual compared with this account's history"];
  const facts = [
    ["Network", `${esc(n.network || "unknown")}${n.asn ? ` (AS${n.asn})` : ""}`],
    ["Connection type", esc(n.type || "unknown")],
    ["IP address", esc(ip.ip)],
    ["IP registered in", esc(n.country || "unknown")],
    ["Takeover model", `riskier than ${v.ato_percentile}% of real sign-ins`],
    ["Attack-IP model", `riskier than ${v.attack_ip_percentile}% of real sign-ins`],
  ];
  if (v.distance_km > 0) facts.push(["Distance from last sign-in", `${fmt(Math.round(v.distance_km))} km`],
    ["Speed needed", `${fmt(Math.round(v.velocity_kmph))} km/h`]);
  $("#verdict").innerHTML = `
    <span class="badge ${v.risk_tier}">${v.risk_tier}</span>
    <p class="say">${say(v)}</p>
    <div class="meter"><div style="width:${v.risk_score}%;background:${TIER_COLOR[v.risk_tier]}"></div></div>
    <p class="fineprint">The model rates it riskier than ${v.risk_score}% of sign-ins in the real test data. Alibi would ${esc(v.recommended_action)}.</p>
    <p class="fineprint tiers">LOW is below the 90th percentile · MEDIUM is the 90th or above · HIGH the 99th or above ·
      CRITICAL the 99.9th or above. A rule (malware server, Tor, new VPN, impossible travel, password guessing) can raise the tier.</p>
    <h3>Why</h3><ul>${reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>
    <div class="facts">${facts.map(([k, val]) => `<div><b>${k}</b>${val}</div>`).join("")}</div>
    <p class="fineprint">History sent first: 7 sign-ins over two weeks from ${esc(usual.network)} in ${CITIES[home][0]}${fails ? `, then ${fails} wrong passwords` : ""}.</p>`;

  tripLayer.clearLayers();
  const a = CITIES[home], b = CITIES[there];
  L.circleMarker([a[1], a[2]], { radius: 7, color: css("--accent"), fillOpacity: 0.9 }).bindTooltip(`Usual: ${a[0]}`).addTo(tripLayer);
  const color = { LOW: css("--ok"), MEDIUM: css("--warn"), HIGH: css("--risk"), CRITICAL: css("--risk") }[v.risk_tier];
  L.circleMarker([b[1], b[2]], { radius: 8, color, fillOpacity: 0.9 }).bindTooltip(`This sign-in: ${b[0]}`).addTo(tripLayer);
  if (home !== there) {
    L.polyline([[a[1], a[2]], [b[1], b[2]]], { color, dashArray: "6 6" }).addTo(tripLayer);
    tripMap.fitBounds([[a[1], a[2]], [b[1], b[2]]], { padding: [40, 40], maxZoom: 5 });
  } else tripMap.setView([a[1], a[2]], 4);
}

// ---------- news ----------
loaders.news = async () => {
  const { news, videos } = await api("/v1/intel/news");
  $("#news-list").innerHTML = news.map((n) => `<li><a href="${esc(n.url)}" target="_blank" rel="noopener">${esc(n.title)}</a>
    <small>${esc(n.source)} · ${ago(n.published)}</small></li>`).join("") || '<li class="muted">Headlines are refreshing. Check back in a few minutes.</li>';
  $("#video-list").innerHTML = videos.map((v) => {
    const id = new URL(v.url).searchParams.get("v");
    return `<li class="vid">${id ? `<img src="https://i.ytimg.com/vi/${esc(id)}/mqdefault.jpg" alt="" loading="lazy">` : "<span></span>"}
      <div><a href="${esc(v.url)}" target="_blank" rel="noopener">${esc(v.title)}</a><small>${esc(v.source)} · ${ago(v.published)}</small></div></li>`;
  }).join("");
  $("#video-list").closest(".card").hidden = !videos.length; // no videos: hide the panel rather than show an error
};

// ---------- data & accuracy ----------
const SPAN = { h: "hour", d: "day" };
const every = (span) => { const n = +span.slice(0, -1), u = SPAN[span.at(-1)]; return n === 1 ? `every ${u}` : `every ${n} ${u}s`; };
const spanMs = (span) => +span.slice(0, -1) * (span.endsWith("h") ? 3600e3 : 86400e3);

loaders.results = async () => {
  const [m, fr, src] = await Promise.all([api("/v1/model"), api("/v1/intel/freshness"), api("/v1/intel/sources")]);
  const ato = m.test_metrics.ato, ip = m.test_metrics.attack_ip;
  $("#model-kpis").innerHTML = [
    kpi(`${ato.confusion_matrix.tp} of ${ato.positives}`, `account takeovers caught in the Oct to Nov 2020 test data (recall ${pct(ato.recall, 1)})`),
    kpi(pct(ato.alert_rate), `of sign-ins asked for a code (${ato.alerts_per_10k_logins} per 10,000)`),
    kpi(ato.roc_auc.toFixed(3), "takeover ROC-AUC (1.0 is perfect, 0.5 is a coin flip)"),
    kpi(ip.roc_auc.toFixed(3), `attack-IP ROC-AUC on Jan to Feb 2021 data, recall ${pct(ip.recall, 1)} at a ${pct(ip.alert_rate)} alert rate`),
    kpi(compact(ato.logins), "test sign-ins the model never saw"),
    kpi(pct(ato.precision, 2), "takeover precision: most codes go to sign-ins not labelled as takeovers, so Alibi asks rather than blocks"),
  ].join("");
  $("#model-plain").textContent = `Out of ${fmt(ato.logins)} sign-ins in the test months (October and November 2020), ${ato.positives} were labelled account takeovers. ` +
    `Asking for a one-time code on the riskiest ${pct(ato.alert_rate)} of sign-ins would have stopped ${ato.confusion_matrix.tp} of them. ` +
    `The other ${fmt(ato.confusion_matrix.fp)} people asked for a code were not labelled as takeovers. ` +
    `With only ${ato.positives} takeovers to test on, that catch rate is uncertain: anywhere from about 43% to 80%. ` +
    `Spotting sign-ins from known attack IPs is harder: the model ranks them well above chance (ROC-AUC ${ip.roc_auc.toFixed(2)}) ` +
    `but catches only ${pct(ip.recall, 1)} at that budget, which is why Alibi adds today's Tor, VPN, malware-server and criminal-network checks on top. ` +
    "These models have not yet been tested on 2025 or 2026 logins.";
  const now = Date.now();
  $("#currency").innerHTML = fr.feeds.map((f) => {
    const age = f.updated ? now - new Date(f.updated) : null;
    const stale = age !== null && age > spanMs(f.max_age);
    const when = !f.available ? (f.optional ? "not in this snapshot; fetched live" : "missing") : `${day(f.updated)} (${ago(f.updated)})`;
    return `<tr><td><a href="${esc(f.url)}" target="_blank" rel="noopener">${esc(f.name)}</a></td><td>${esc(f.licence)}</td>
      <td>${when}${stale ? ' <span class="tag">stale</span>' : ""}</td><td>${every(f.cadence)}</td></tr>`;
  }).join("");
  $("#currency-note").textContent = `Snapshot built ${day(fr.snapshot)}. A feed counts as stale once it is older than its limit: 3 days for the malware feeds, up to 6 months for DB-IP and the cable maps.`;
  $("#model-data").innerHTML = fr.models.map((x) => `<tr><td>${esc(x.name)}</td><td><a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.data)}</a>, ${esc(x.licence)}<br><span class="fineprint">${esc(x.note)}</span></td>
    <td>${esc(x.train)}</td><td>${esc(x.test)}</td></tr>`).join("");
  const { news_feeds: nf, video_feeds: vf } = src;
  const rows = [
    [`Security news: ${Object.keys(nf).join(", ")}`, Object.values(nf)[0], "public RSS feeds, headlines and links only, fetched live"],
    [`Videos: ${Object.keys(vf).join(", ")}`, "https://www.youtube.com", "public YouTube channel feeds, titles and links only, fetched live"],
    ["Country shapes: Natural Earth via world-atlas", "https://github.com/topojson/world-atlas", "public domain"],
    ["Earth imagery: NASA Blue Marble", "https://visibleearth.nasa.gov/collection/1484/blue-marble", "public domain"],
    ["Street map tiles", "https://www.openstreetmap.org/copyright", "© OpenStreetMap contributors, ODbL"],
  ];
  $("#sources").innerHTML = rows.map(([n, u, l]) => `<li><a href="${esc(u)}" target="_blank" rel="noopener">${esc(n)}</a>: ${esc(l)}</li>`).join("");
};

show(location.hash.slice(1) || "home");
