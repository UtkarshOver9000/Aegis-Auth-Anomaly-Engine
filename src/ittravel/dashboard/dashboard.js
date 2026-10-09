// Alibi dashboard. Every number on the page comes from the API, which reads the real data
// snapshot (HIBP, CISA KEV, abuse.ch, Spamhaus, RansomLook, iptoasn, OONI, TeleGeography,
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
  if (!rows.length) return void (el.innerHTML = '<p class="muted empty">Nothing recorded in this snapshot.</p>');
  const max = Math.max(...rows.map((r) => r[1]), 1);
  el.innerHTML = rows.map(([k, n]) => `<div class="bar"><span>${esc(k)}</span>
    <div class="track"><div class="fill" style="width:${(n / max) * 100}%"></div></div><span class="n">${label(n)}</span></div>`).join("");
}

// ---------- tabs ----------
const loaders = {};
const loaded = new Set();

// "Updated 3 hours ago" line under a tab's title
function stamp(tab, iso, extra = "") {
  const section = $(`#tab-${tab}`);
  if (!section.querySelector(".page-head")) return; // the globe shows its date in the timeline
  let el = section.querySelector(".updated");
  if (!el) {
    section.querySelector(".page-head").insertAdjacentHTML("afterend", '<p class="fineprint updated"></p>');
    el = section.querySelector(".updated");
  }
  el.textContent = `Updated ${ago(iso)} (${day(iso)})${extra}`;
}

// Run a tab's loader with a skeleton while it loads and a retry card if it fails; never a blank panel.
function load(tab) {
  const section = $(`#tab-${tab}`);
  loaded.add(tab);
  section.querySelector(".load-error")?.remove();
  section.classList.add("is-loading");
  loaders[tab]()
    .catch((err) => {
      console.error(tab, err);
      loaded.delete(tab);
      (section.querySelector(".page-head") || section.firstElementChild).insertAdjacentHTML("afterend", `<div class="panel load-error" role="alert">
        <b>This section didn't load.</b> The server or your connection had a hiccup (${esc(err.message.slice(0, 80))}).
        <button class="btn">Try again</button></div>`);
      section.querySelector(".load-error button").addEventListener("click", () => load(tab));
    })
    .finally(() => section.classList.remove("is-loading"));
}

function show(hash) {
  // "#check/travel" opens a tab and, for the sign-in check, runs that story
  let [tab, story] = hash.split("/");
  if (!$(`#tab-${tab}`)) tab = "home";
  $$(".tab").forEach((s) => (s.hidden = s.id !== `tab-${tab}`));
  $$("nav a").forEach((a) => a.classList.toggle("on", a.dataset.tab === tab));
  if (!loaded.has(tab) && loaders[tab]) load(tab);
  if (tab === "check" && tripMap) setTimeout(() => tripMap.invalidateSize(), 50);
  document.body.classList.toggle("on-globe", tab === "globe");
  if (tab === "globe" && globe) setTimeout(sizeGlobe, 50);
  window.scrollTo(0, 0);
  if (tab === "check" && PRESETS[story]) applyPreset(story);
}
window.addEventListener("hashchange", () => show(location.hash.slice(1)));

// ---------- global search ----------
$("#search").addEventListener("submit", async (e) => {
  e.preventDefault();
  const q = $("#search-q").value.trim();
  const box = $("#search-results");
  if (q.length < 2) return void (box.hidden = true);
  box.hidden = false;
  box.innerHTML = '<p class="muted">Searching…</p>';
  try {
    box.innerHTML = searchHtml(await api(`/v1/intel/search?q=${encodeURIComponent(q)}`)) +
      '<p><button class="link" id="search-close">Close</button></p>';
  } catch (err) {
    box.innerHTML = `<p class="err">Search failed: ${esc(err.message.slice(0, 80))}</p>`;
  }
  $("#search-close")?.addEventListener("click", () => (box.hidden = true));
});

function searchHtml(r) {
  if (r.kind === "ip") {
    const n = r.ip, rep = r.report;
    return `<h3>${esc(r.query)}</h3><p><b>${esc(n.type)}</b>${n.network ? ` on ${esc(n.network)} (AS${n.asn})` : ""}${
      n.country ? `, registered in ${esc(n.country)}` : ""}.</p>` +
      (rep ? `<p class="err">Reported as a ${esc(rep.what.toLowerCase())} (${esc(rep.malware)}) to abuse.ch ${esc(rep.source)} on ${day(rep.seen)}.</p>`
        : "<p class=\"muted\">Not on the abuse.ch malware lists in this snapshot.</p>") +
      (n.criminal_network ? "<p class=\"err\">Its network is on the Spamhaus DROP list (run by criminals).</p>" : "") +
      `<p class="fineprint"><a href="/v1/intel/ip/${encodeURIComponent(r.query)}/stix" target="_blank">Download as STIX 2.1</a></p>`;
  }
  if (r.kind === "cve") {
    return r.flaws.length ? r.flaws.map((f) => `<h3>${esc(f.cve)}</h3><p>${esc(f.name)}</p>
      <p class="fineprint">Added to CISA's exploited list ${day(f.added)}${f.ransomware ? " · used by ransomware" : ""} ·
      <a href="https://nvd.nist.gov/vuln/detail/${esc(f.cve)}" target="_blank" rel="noopener">NVD</a></p>`).join("")
      : `<p class="muted">${esc(r.query)} is not on CISA's list of exploited flaws.</p>`;
  }
  const b = r.breaches.map((x) => `<li><b>${esc(x.name)}</b> ${esc(x.domain)}: ${fmt(x.accounts)} accounts, ${day(x.breach_date)} · ${esc(x.how)}</li>`).join("");
  const f = r.flaws.map((x) => `<li><b>${esc(x.cve)}</b> ${esc(x.vendor)} ${esc(x.product)} · added ${day(x.added)}</li>`).join("");
  return `<h4>Breaches (${fmt(r.breach_matches)})</h4>${b ? `<ul>${b}</ul>` : '<p class="muted">No published breach matches.</p>'}
    <h4>Exploited flaws (${fmt(r.flaw_matches)})</h4>${f ? `<ul>${f}</ul>` : '<p class="muted">No exploited flaw matches.</p>'}`;
}

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

// ---------- header status ----------
async function headerStatus() {
  try {
    const h = await api("/v1/health");
    const ok = h.feeds.filter((f) => f.status === "ok" || f.status.startsWith("optional")).length;
    const el = $("#status");
    el.className = `status ${h.status}`;
    el.querySelector("span").textContent = `SNAPSHOT ${new Date(h.snapshot).toISOString().slice(5, 16).replace("T", " ")}Z · ${ok}/${h.feeds.length} FEEDS OK`;
    el.title = h.feeds.filter((f) => f.status !== "ok").map((f) => `${f.id}: ${f.status}`).join("\n") || "All feeds within their max age";
  } catch {
    $("#status span").textContent = "STATUS UNAVAILABLE";
  }
}

// ---------- overview ----------
const hhmm = (unix) => new Date(unix * 1000).toISOString().slice(5, 16).replace("T", " ") + "Z";

loaders.home = async () => {
  const [o, act, f, b, t] = await Promise.all([api("/v1/intel/overview"), api("/v1/intel/activity"), api("/v1/intel/flaws"),
    api("/v1/intel/breaches"), api("/v1/intel/threats")]);
  stamp("home", o.as_of, " · threat feeds refresh every 6 h; news is live");
  const tk = o.takeovers_caught, rw = o.ransomware_victims;
  $("#home-kpis").innerHTML = [
    kpi(fmt(o.malicious_ips), "malware and botnet servers tracked"),
    kpi(fmt(act.new_today), "new malware servers reported today (UTC)"),
    kpi(fmt(rw.victims), `ransomware leak-site posts, ${day(rw.from)} to ${day(rw.to)}`),
    kpi(fmt(o.exploited_flaws_last_30_days), "flaws newly confirmed exploited, 30 d"),
    kpi(compact(o.accounts_exposed_last_12_months), `accounts exposed in ${o.breaches_last_12_months} breaches, 12 mo`),
    kpi(fmt(o.criminal_networks), "networks run by criminals (Spamhaus)"),
    kpi(fmt(o.countries_with_confirmed_blocking), "countries with confirmed website blocking, 30 d"),
    tk ? kpi(`${tk.caught}/${tk.of}`, `takeovers caught at a ${pct(tk.challenge_rate)} challenge rate (2020 test data)`)
      : kpi("rules only", "takeover model not deployed on this server"),
  ].join("");
  const max = Math.max(...act.per_hour, 1);
  $("#home-activity").innerHTML = act.per_hour.map((n, i) => `<i style="height:${(n / max) * 100}%" title="${n} reported, ${47 - i} h before snapshot"></i>`).join("");
  $("#home-activity-meta").textContent = `${fmt(act.last_48h)} total`;
  $("#home-flaws").innerHTML = f.latest.slice(0, 7).map((r) => `<li><span><a href="https://nvd.nist.gov/vuln/detail/${esc(r.cve)}" target="_blank" rel="noopener">${esc(r.cve)}</a>
    ${esc(r.vendor)} ${esc(r.product)}</span><span>${r.epss == null ? "" : `EPSS ${pct(r.epss, 1)} · `}${esc(r.added.slice(5))}</span></li>`).join("");
  $("#home-breaches").innerHTML = b.latest.slice(0, 7).map((r) => `<li><span><b>${esc(r.name)}</b> <span class="muted">${esc(r.how)}</span></span><span>${compact(r.accounts)}</span></li>`).join("");
  bars($("#home-gangs"), t.ransomware.by_group.slice(0, 7));
  $("#home-asof").textContent = `Snapshot ${o.as_of}. Sources and licences: Sources tab.`;
};

// ---------- live globe ----------
const METRICS = {
  malicious_ips: {
    state: "m",
    title: "Malware and botnet servers",
    explain: "Servers reported to abuse.ch for spreading malware or controlling botnets, placed by IP geolocation and divided by the IPv4 addresses in each state. Hijacked home routers and cameras dominate, so dense home-broadband regions rank high.",
    source: "malware",
  },
  dns_resolvers: {
    state: "d",
    title: "Public DNS servers",
    explain: "Working open DNS resolvers per million IPv4 addresses. Useful infrastructure, also abused for traffic amplification and blocked under censorship.",
    source: "dns",
  },
  confirmed_blocks: {
    title: "Websites confirmed blocked, 30 d",
    explain: "OONI Probe tests that hit a known government or ISP block page. Country-level; more volunteers means more tests.",
    source: "censorship",
  },
  hosting_ipv4: {
    title: "Hosting / VPN address space",
    explain: "IPv4 addresses owned by cloud, hosting and VPN providers. Country-level. Sign-ins from these networks get extra scrutiny.",
    source: "network",
  },
  cable_landings: {
    title: "Undersea cable landing stations",
    explain: "Where undersea internet cables come ashore. Country-level. Few landings means a single fault can cut a country off.",
    source: "cables",
  },
  tor_exits: {
    title: "Tor exit relays",
    explain: "Relays where Tor traffic leaves the network. Country-level. A sign-in from one could originate anywhere.",
    source: "tor",
  },
};
const POINT_COLORS = { c2: "#d55e00", dl: "#e69f00", tor: "#cc79a7", drop: "#f0e442", landing: "#56b4e9" };
let metric = "malicious_ips", globe, selected, journey = [], journeyArcs = [], legendData = null;

function sizeGlobe() {
  const el = $("#globe");
  if (globe && el.clientWidth) globe.width(el.clientWidth).height(el.clientHeight);
}

const IMG = "/static/vendor/img/"; // NASA Blue Marble imagery (public domain), self-hosted
// Phones and tablets get 2048-pixel textures; desktops keep the full 4096.
const SMALL_SCREEN = matchMedia("(pointer: coarse)").matches || innerWidth < 900;
const TEX_W = SMALL_SCREEN ? 2048 : 4096;
const REDUCED_MOTION = matchMedia("(prefers-reduced-motion: reduce)").matches;
let places = [], pickData = null, pickW = 0, pickH = 0, heatPromise, cablesLoaded = null, selState = null, snapshotAt = "";
let events = { points: [], types: {} }, cablePaths = [], landingPoints = [], flat = false;

// The server paints each metric's states into the Earth texture (see intel/globe.py), so the browser
// downloads one image instead of drawing 4,596 states itself.
const texUrl = (m) => `/v1/intel/globe/${m}.jpg?w=${TEX_W}&v=${encodeURIComponent(snapshotAt)}`;

function webglWorks() {
  try {
    const c = document.createElement("canvas");
    return !!(window.WebGLRenderingContext && (c.getContext("webgl2") || c.getContext("webgl")));
  } catch {
    return false;
  }
}

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

const perMillion = (count, ip) => (ip >= 100000 ? `${(count / ip * 1e6).toFixed(2)} per 1M addresses` : "too few addresses to rate");

function activePoints() {
  const on = new Set($$("[data-layer]").filter((c) => c.checked).map((c) => c.dataset.layer));
  const pts = events.points.filter((p) => on.has(p[2])).map(([lat, lng, kind]) => ({ lat, lng, kind }));
  return $("#show-cables").checked ? pts.concat(landingPoints) : pts;
}

function refreshPoints() {
  if (!globe || flat) return;
  globe.pointsData(activePoints());
}

// Flat fallback for phones or browsers without WebGL: the same server texture as a 2D map you can tap.
function flatMap(features) {
  flat = true;
  const el = $("#globe");
  el.classList.add("flat");
  el.innerHTML = `<img alt="Map of ${esc(METRICS[metric].title)}" src="${texUrl(metric)}">`;
  el.querySelector("img").addEventListener("click", (e) => {
    const r = e.target.getBoundingClientRect();
    const at = { lng: ((e.clientX - r.left) / r.width) * 360 - 180, lat: 90 - ((e.clientY - r.top) / r.height) * 180 };
    pickAt(features, at);
  });
}

loaders.globe = async () => {
  const el = $("#globe");
  el.innerHTML = `<div class="globe-poster"><span>LOADING GLOBE</span></div>`;
  const useGl = webglWorks();
  const [{ features, data, centers }, ev, act] = await Promise.all([world(), api("/v1/intel/events"), api("/v1/intel/activity"),
    useGl ? need("globe") : null, loadPickMap()]);
  snapshotAt = data.as_of;
  events = ev;
  for (const k of ["c2", "dl", "tor", "drop"]) {
    const n = ev.points.filter((p) => p[2] === k).length;
    const box = $(`[data-count="${k}"]`);
    if (box) box.textContent = fmt(n);
    if (!n) $(`[data-layer="${k}"]`)?.closest("label")?.remove();
  }
  if (!data.totals.tor_exit_relays) $('[data-metric="tor_exits"]').remove();
  globe = null;
  if (useGl) {
    try {
      globe = Globe({ animateIn: !REDUCED_MOTION, rendererConfig: { antialias: !SMALL_SCREEN, powerPreference: "high-performance" } })(el);
    } catch (err) {
      console.error("WebGL globe failed, using the flat map", err);
    }
  }
  setupTimeline(act);
  globe ? setupGlobe(el, features, data, centers) : flatMap(features);
  globe && (globe.__features = features);
  window.__features = features;
  window.__data = data;
  window.__centers = centers;

  $$("[data-metric]").forEach((b) => b.addEventListener("click", () => {
    metric = b.dataset.metric;
    $$("[data-metric]").forEach((x) => x.classList.toggle("on", x === b));
    paint();
    if (selected) selectCountry(selected, window.__lastAt);
  }));
  $$("[data-layer]").forEach((c) => c.addEventListener("change", refreshPoints));
  $("#show-cables").addEventListener("change", async () => {
    if (!globe) return;
    const on = $("#show-cables").checked;
    if (on) cablesLoaded ??= api("/v1/intel/cables"); // the 733 cable paths load only when asked for
    const cab = on ? await cablesLoaded : null;
    cablePaths = on ? cab.cables.flatMap((c) => c.paths.map((p) => ({ name: c.name, color: c.color, coords: p }))) : [];
    landingPoints = on ? cab.landings.map((l) => ({ lat: l.lat, lng: l.lng, kind: "landing" })) : [];
    globe.pathsData(cablePaths);
    refreshPoints();
  });
  $$("[data-toggle]").forEach((b) => b.addEventListener("click", () => {
    const target = $(`#${b.dataset.toggle}`);
    const open = !target.classList.contains("open");
    $$(".ov-left, .ov-right").forEach((p) => p.classList.remove("open"));
    target.classList.toggle("open", open);
  }));
  $$("[data-journey]").forEach((b) => b.addEventListener("click", () => {
    journey = b.dataset.journey.split(",");
    renderJourney();
    runJourney();
  }));
  $("#journey-go").addEventListener("click", runJourney);
  $("#tour-btn").addEventListener("click", () => (touring ? stopTour() : tour()));
  paint();
  if (new URLSearchParams(location.search).has("tour")) tour();
};

function setupGlobe(el, features, data, centers) {
  globe
    .globeImageUrl(texUrl(metric))
    .showAtmosphere(true).atmosphereColor("#4c90f0").atmosphereAltitude(0.14)
    .onGlobeClick((at) => pickAt(features, at))
    .polygonsData([]).polygonCapColor(() => "rgba(255,255,255,0.18)").polygonSideColor(() => "rgba(0,0,0,0)")
    .polygonStrokeColor(() => "#ffffff").polygonAltitude(0.006)
    .onPolygonClick((_p, _e, at) => pickAt(features, at))
    .pathPoints("coords").pathPointLat((p) => p[0]).pathPointLng((p) => p[1]).pathPointAlt(0.004)
    .pathColor((p) => p.color).pathDashLength(0.08).pathDashGap(0.01).pathDashAnimateTime(16000).pathTransitionDuration(0)
    .pathLabel((p) => `<div class="globe-tip">Undersea cable: ${esc(p.name)}</div>`)
    .onPathClick((_p, _e, at) => pickAt(features, at))
    .pointLat("lat").pointLng("lng").pointAltitude(0.004).pointRadius((p) => (p.kind === "landing" ? 0.12 : 0.16))
    .pointColor((p) => POINT_COLORS[p.kind]).pointsMerge(true).pointsTransitionDuration(0)
    .ringLat("lat").ringLng("lng").ringColor((r) => (t) => `rgba(${r.rgb},${1 - t})`).ringMaxRadius(2.6)
    .ringPropagationSpeed(3).ringRepeatPeriod(0)
    .arcsData([]).arcColor("color").arcStroke(0.8).arcDashLength(0.5).arcDashGap(0.15).arcDashAnimateTime(1600)
    .arcAltitudeAutoScale(0.45).arcLabel((a) => `<div class="globe-tip">${esc(a.label)}</div>`)
    .labelsData([]).labelLat("lat").labelLng("lng").labelText("text").labelSize(1.1).labelDotRadius(0.45)
    .labelColor(() => "#ffffff").labelResolution(2);
  if (!SMALL_SCREEN) globe.bumpImageUrl(`${IMG}earth-topology.png`).backgroundImageUrl(`${IMG}night-sky.png`);
  globe.renderer().setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
  globe.pointOfView({ lat: 22, lng: 40, altitude: SMALL_SCREEN ? 2.6 : 1.9 });
  Object.assign(globe.controls(), { autoRotate: !REDUCED_MOTION && !SMALL_SCREEN, autoRotateSpeed: 0.3, minDistance: 112, maxDistance: 600 });
  $("#reset-view").addEventListener("click", () => globe.pointOfView({ lat: 22, lng: 40, altitude: 1.9 }, 800));
  el.addEventListener("pointerdown", () => (globe.controls().autoRotate = false), { once: true });
  // a lost WebGL context (common on phones under memory pressure) falls back to the flat map
  el.querySelector("canvas")?.addEventListener("webglcontextlost", () => { globe.pauseAnimation(); flatMap(features); paint(); });
  sizeGlobe();
  new ResizeObserver(sizeGlobe).observe(el);
  new IntersectionObserver(([e]) => (e.isIntersecting ? globe.resumeAnimation() : globe.pauseAnimation())).observe(el);
  refreshPoints();

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
      tip.style.left = `${Math.min(e.clientX - box.left + 14, box.width - 270)}px`;
      tip.style.top = `${e.clientY - box.top + 14}px`;
      tip.innerHTML = stateTip(s);
    });
  });
  el.addEventListener("mouseleave", () => (tip.hidden = true));
}

// ---------- 48-hour replay: each malware server pulses where and when it was reported ----------
let replay = null;

function setupTimeline(act) {
  $("#new-today").textContent = fmt(act.new_today);
  $("#last-48h").textContent = fmt(act.last_48h);
  const max = Math.max(...act.per_hour, 1);
  $("#replay-hist").innerHTML = act.per_hour.map((n, i) => `<i style="height:${(n / max) * 100}%" title="${n} reported ${47 - i}-${48 - i} h before the snapshot"></i>`).join("");
  $("#replay-time").textContent = `window ends ${hhmm(act.window_end)}`;
  $("#replay-play").addEventListener("click", () => (replay ? stopReplay() : startReplay(act)));
}

function startReplay(act, seconds = 36) {
  const end = act.window_end, start = end - 48 * 3600;
  const timed = events.points.filter((p) => p[3] && p[3] >= start && p[3] <= end).sort((a, b) => a[3] - b[3]);
  const bars = $$("#replay-hist i");
  const rgb = { c2: "213,94,0", dl: "230,159,0" };
  let k = 0;
  const t0 = performance.now();
  $("#replay-play").textContent = "❚❚";
  replay = { stop: false };
  const step = () => {
    if (!replay || replay.stop) return;
    const now = start + ((performance.now() - t0) / (seconds * 1000)) * 48 * 3600;
    const fresh = [];
    while (k < timed.length && timed[k][3] <= now) {
      const [lat, lng, kind] = timed[k++];
      fresh.push({ lat, lng, rgb: rgb[kind] || "230,159,0" });
    }
    if (fresh.length && globe) globe.ringsData([...globe.ringsData().slice(-120), ...fresh]);
    const hour = Math.min(47, Math.floor((now - start) / 3600));
    bars.forEach((b, i) => b.classList.toggle("past", i <= hour));
    $("#replay-time").textContent = `${hhmm(Math.min(now, end))} · ${fmt(k)} reported`;
    if (now >= end) return stopReplay(true);
    requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function stopReplay(done = false) {
  if (replay) replay.stop = true;
  replay = null;
  $("#replay-play").textContent = "▶";
  if (!done) $$("#replay-hist i").forEach((b) => b.classList.remove("past"));
  setTimeout(() => globe && globe.ringsData([]), done ? 2500 : 0);
}

// ---------- tour: a hands-free walk through today's real hotspots ----------
let touring = false;
const pause = (ms) => new Promise((r) => setTimeout(r, ms));

function caption(label, text) {
  const c = $("#tour-caption");
  c.hidden = !text;
  c.innerHTML = text ? `<span class="label">${esc(label)}</span>${text}` : "";
}

async function tour() {
  if (!globe || touring) return;
  touring = true;
  $("#tour-btn").textContent = "Stop tour";
  globe.controls().autoRotate = false;
  try {
    const lg = await api("/v1/intel/globe/malicious_ips/legend");
    const act = await api("/v1/intel/activity");
    if (metric !== "malicious_ips") $('[data-metric="malicious_ips"]').click();
    const o = await api("/v1/intel/overview");
    caption("Today", `${fmt(o.malicious_ips)} malware and botnet servers tracked; ${fmt(act.new_today)} reported since 00:00 UTC.`);
    globe.pointOfView({ lat: 20, lng: 40, altitude: 2.2 }, 1500);
    await pause(4000);
    for (const top of lg.top.filter((x) => x.lat != null).slice(0, 3)) {
      if (!touring) return;
      globe.pointOfView({ lat: top.lat, lng: top.lng, altitude: 0.9 }, 2200);
      caption("Hotspot", `<b>${esc(top.name)}</b>: ${top.value.toFixed(2)} malware servers per 1M addresses (${fmt(top.count)} servers).`);
      await pause(4500);
    }
    if (!touring) return;
    globe.pointOfView({ lat: 25, lng: 60, altitude: 2.3 }, 1800);
    caption("Replay", "The last 48 hours, each malware server shown where and when it was reported.");
    await pause(1800);
    startReplay(act, 14);
    await pause(15500);
    if (!touring) return;
    journey = ["IN", "GB"];
    renderJourney();
    caption("Sign-in check", "One account signs in from India, then from the UK 45 minutes later.");
    await runJourney();
    await pause(4500);
  } finally {
    stopTour();
  }
}

function stopTour() {
  touring = false;
  $("#tour-btn").textContent = "Tour";
  caption("", "");
}

function pickAt(features, at) {
  const f = at && features.find((x) => d3.geoContains(x, [at.lng, at.lat]));
  if (f) selectCountry(f, at);
}

function stateTip(s) {
  const c = window.__data.countries[s.c];
  const m = METRICS[metric];
  const rate = m.state ? `<br>${perMillion(m.state === "m" ? s.m : s.d, s.ip)}` : "";
  return `<b>${esc(s.n)}</b> <span class="muted">${esc(s.t)}${c ? `, ${esc(c.name)}` : ""}</span>
    <br>${fmt(s.m)} malware servers · ${fmt(s.d)} public DNS servers${rate}` +
    (c && !m.state ? `<br>${esc(c.name)} (country): ${fmt(c[metric])}` : "");
}

async function paint() {
  const data = window.__data;
  const m = METRICS[metric];
  if (globe) globe.globeImageUrl(texUrl(metric));
  else $("#globe img") && ($("#globe img").src = texUrl(metric));
  const lg = (legendData = await api(`/v1/intel/globe/${metric}/legend`));
  stamp("globe", lg.as_of, "");
  $("#legend").innerHTML = `<div class="label">${esc(lg.unit)}${lg.level === "country" ? " · country-level" : ""}</div><div class="bins">` +
    [...lg.bins, lg.no_data].map((b) => `<span><i style="background:${b.color}"></i>${esc(b.label)}</span>`).join("") + "</div>";
  $("#top-title").textContent = `Top 10 ${lg.level === "state" ? "states" : "countries"} · ${m.title}`;
  $("#top-list").innerHTML = lg.top.map((t) => `<li><span>${esc(t.name)}</span><b>${fmt(t.value)}</b></li>`).join("");
  $("#metric-explain").textContent = m.explain;
  const s = data.sources[m.source];
  const how = lg.level === "state"
    ? ` Placed by IP Geolocation by <a href="https://db-ip.com" target="_blank" rel="noopener">DB-IP</a> (CC BY 4.0); states under ${fmt(lg.min_addresses)} addresses are grey.`
    : "";
  $("#map-sources").innerHTML = s ? `Source: <a href="${s.url}" target="_blank" rel="noopener">${esc(s.name)}</a> (${esc(s.license)}).${how} Colours: ColorBrewer YlOrRd.` : "";
}

async function highlightState(s) {
  if (!globe) return;
  if (!s) return globe.polygonsData([]);
  const { rings } = await api(`/v1/intel/globe/state/${s.i}`);
  globe.polygonsData([{ type: "Feature", properties: {}, geometry: { type: "MultiPolygon",
    coordinates: rings.map((r) => [r.map(([lat, lng]) => [lng, lat])]) } }]);
}

async function selectCountry(f, at) {
  const c = f.properties.c;
  if (!c) return;
  selected = f;
  window.__lastAt = at;
  const st = stateAt(at);
  selState = st && st.c === c.a2 ? st : null;
  highlightState(selState);
  const [lng, lat] = window.__centers[c.a2];
  if (globe) {
    globe.controls().autoRotate = false;
    if (!touring) globe.pointOfView(at ? { lat: at.lat, lng: at.lng, altitude: 1.2 } : { lat, lng, altitude: 1.5 }, 900);
  }
  if (SMALL_SCREEN) { $$(".ov-left").forEach((p) => p.classList.remove("open")); $("#inspector").classList.add("open"); }
  const rank = legendData?.ranks?.[c.a2];
  const facts = [
    ["Malware servers", fmt(c.malicious_ips)],
    ["Websites blocked, 30 d", `${fmt(c.confirmed_blocks)} / ${compact(c.censorship_measurements)} tests`],
    ["Public DNS servers", fmt(c.dns_resolvers)],
    ["Hosting / VPN addresses", compact(c.hosting_ipv4)],
    ["Cable landings", fmt(c.cable_landings)],
  ];
  if (window.__data.totals.tor_exit_relays) facts.push(["Tor exits", fmt(c.tor_exits)]);
  const key = METRICS[metric].state === "d" ? "d" : "m";
  const label = key === "d" ? "public DNS servers" : "malware servers";
  const topStates = places.filter((s) => s.c === c.a2 && s[key] > 0).sort((a, b) => b[key] - a[key]).slice(0, 6);
  heatPromise ??= api("/v1/intel/heat"); // city lists load only when a country is opened
  const spots = (await heatPromise).places?.[c.a2]?.[key === "d" ? "dns" : "malware"] || [];
  $("#country-panel").innerHTML = `<h3>Inspector <span class="meta">${esc(c.a2)}</span></h3>
    ${selState ? `<div class="place"><b>${esc(selState.n)}</b> <span class="muted">${esc(selState.t)}</span><br>
      ${fmt(selState.m)} malware servers · ${fmt(selState.d)} public DNS servers
      <br><span class="muted">${perMillion(selState[key], selState.ip)} (${label})</span></div>` : ""}
    <div class="row"><b style="font-size:16px">${esc(c.name)}</b></div>
    ${rank ? `<p class="rank">#${rank[0]} of ${rank[2]} · ${esc(METRICS[metric].title)} (${fmt(rank[1])})</p>` : ""}
    <div class="facts">${facts.map(([k, v]) => `<div><b>${k}</b>${v}</div>`).join("")}</div>
    ${topStates.length ? `<p class="fineprint"><b>Top states, ${label}:</b> ${topStates.map((s) => `${esc(s.n)} ${fmt(s[key])}`).join(" · ")}</p>` : ""}
    ${spots.length ? `<p class="fineprint"><b>Top cities:</b> ${spots.slice(0, 6).map(([city, n]) => `${esc(city)} ${fmt(n)}`).join(" · ")}</p>` : ""}
    <p class="fineprint" id="country-nets">Looking up networks…</p>
    <button class="btn" id="add-journey" ${journey.length >= 3 ? "disabled" : ""}>Add to journey</button>`;
  $("#add-journey").addEventListener("click", () => {
    if (journey.length < 3 && journey.at(-1) !== c.a2) journey.push(c.a2);
    $("#journey-panel").open = true;
    renderJourney();
    $("#add-journey").disabled = journey.length >= 3;
  });
  try {
    const s = await samples(c.a2);
    const homes = s.home.map((h) => esc(h.network)).join(", ");
    $("#country-nets").innerHTML = (homes ? `Largest home networks: ${homes}.` : "No home networks on record.") +
      (s.malware ? ` Reported malware server: <span class="mono">${esc(s.malware)}</span>.` : "");
  } catch {
    $("#country-nets").textContent = "";
  }
}

function renderJourney() {
  const names = window.__data.countries;
  $("#journey-list").innerHTML = journey.map((cc, i) => `<li>${esc(names[cc].name)}${i === 0 ? " <span class='muted'>(usual home)</span>" : ""}
    <button data-drop="${i}" aria-label="Remove">remove</button></li>`).join("");
  $$("[data-drop]").forEach((b) => b.addEventListener("click", () => {
    journey.splice(+b.dataset.drop, 1);
    renderJourney();
  }));
  $("#journey-go").disabled = journey.length < 2;
  const pts = journey.map((cc) => ({ lat: window.__centers[cc][1], lng: window.__centers[cc][0], text: names[cc].name }));
  if (globe) globe.labelsData(pts);
  journeyArcs = pts.slice(1).map((p, i) => ({ startLat: pts[i].lat, startLng: pts[i].lng, endLat: p.lat, endLng: p.lng,
    color: [css("--accent"), css("--accent")], label: `${pts[i].text} → ${p.text}` }));
  if (globe) globe.arcsData(journeyArcs);
  $("#journey-result").innerHTML = "";
}

async function runJourney() {
  if (journey.length < 2) return;
  const names = window.__data.countries, centers = window.__centers;
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
    if (globe) globe.arcsData([...journeyArcs]);
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
  stamp("breaches", s.as_of, ". Breach list from Have I Been Pwned, refreshed daily.");
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
  stamp("attacks", t.as_of, ". Malware feeds refresh daily.");
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
  $("#ransom-window").textContent = `${fmt(rw.victims)} posts on ransomware gangs' leak sites between ${day(rw.from)} and ${day(rw.to)} (RansomLook, CC BY 4.0). ` +
    "Only totals are shown: no victim names, links or stolen files. This source does not record victims' countries or industries.";
  bars($("#ransom-days"), rw.by_day.map(([d, n]) => [day(d), n]));
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
  stamp("flaws", f.as_of, ". CISA adds flaws on weekdays; refreshed daily.");
  $("#flaw-kpis").innerHTML = [
    kpi(fmt(f.added_last_7_days), "added in the last 7 days"),
    kpi(fmt(f.added_last_30_days), "added in the last 30 days"),
    kpi(fmt(f.total), "exploited flaws on the list"),
    kpi(fmt(f.ransomware_linked), "used in ransomware attacks"),
  ].join("");
  bars($("#flaw-vendors"), f.top_vendors_last_12_months);
  const stack = new Set(["Microsoft", "Fortinet", "Cisco"]);
  const chips = $("#stack-chips");
  chips.innerHTML = f.top_vendors.slice(0, 12).map(([v]) => `<button data-vendor="${esc(v)}">${esc(v)}</button>`).join("");
  const rank = async () => {
    $$("[data-vendor]", chips).forEach((b) => b.classList.toggle("on", stack.has(b.dataset.vendor)));
    const r = await api(`/v1/intel/flaws/priority?vendors=${encodeURIComponent([...stack].join(","))}`);
    $("#priority-rows").innerHTML = r.flaws.slice(0, 10).map((x) => {
      const why = [x.epss != null ? `${pct(x.epss, 1)} exploit chance` : null, x.ransomware ? "used by ransomware" : null,
        `added ${day(x.added)}`].filter(Boolean).join(" · ");
      return `<tr><td><b>${x.priority.toFixed(0)}</b></td><td><a href="https://nvd.nist.gov/vuln/detail/${esc(x.cve)}" target="_blank" rel="noopener">${esc(x.cve)}</a></td>
        <td>${esc(x.vendor)} ${esc(x.product)}</td><td class="fineprint">${why}</td></tr>`;
    }).join("") || '<tr><td colspan="4" class="muted">Pick at least one vendor.</td></tr>';
  };
  chips.addEventListener("click", (e) => {
    const v = e.target.closest("[data-vendor]")?.dataset.vendor;
    if (!v) return;
    stack.has(v) ? stack.delete(v) : stack.add(v);
    rank();
  });
  rank();
  const thisMonth = f.as_of.slice(0, 7); // the snapshot's month is not over yet
  bars($("#flaw-months"), Object.entries(f.added_by_month).map(([m, n]) => [
    new Date(`${m}-01`).toLocaleDateString("en-GB", { month: "short", year: "numeric" }) + (m === thisMonth ? ", to date" : ""), n]));
  $("#flaw-rows").innerHTML = f.latest.map((r) => `<tr><td>${day(r.added)}</td>
    <td><a href="https://nvd.nist.gov/vuln/detail/${esc(r.cve)}" target="_blank" rel="noopener">${esc(r.cve)}</a><br>${esc(r.name)}</td>
    <td>${esc(r.vendor)} ${esc(r.product)}</td><td>${r.ransomware ? '<span class="tag">yes</span>' : "not known"}</td>
    <td class="num">${r.epss == null ? "not scored" : pct(r.epss, 1)}</td></tr>`).join("");
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
  api("/v1/model").then(() => $("#tab-check .updated") || $("#tab-check .page-head").insertAdjacentHTML("afterend",
    '<p class="fineprint updated">Network checks use today\'s threat data; the model was trained on 2020 to 2021 logins.</p>'));
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
    btn.textContent = "Run check";
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
  $("#verdict").innerHTML = `<h3>Verdict</h3>
    <span class="badge ${v.risk_tier}">${v.risk_tier}</span>
    <p class="say">${say(v)}</p>
    <div class="meter"><div style="width:${v.risk_score}%;background:${TIER_COLOR[v.risk_tier]}"></div></div>
    <p class="fineprint">The model rates it riskier than ${v.risk_score}% of sign-ins in the real test data. Alibi would ${esc(v.recommended_action)}.</p>
    <p class="fineprint tiers">LOW is below the 90th percentile · MEDIUM is the 90th or above · HIGH the 99th or above ·
      CRITICAL the 99.9th or above. A rule (malware server, Tor, new VPN, impossible travel, password guessing) can raise the tier.</p>
    <details class="howto"><summary>How to read this</summary>
      <p>The percentile compares this sign-in with ${fmt(5403650)} real sign-ins from the model's test data. Riskier than
      99% means only 1 sign-in in 100 looked riskier to the model. The tier turns that into an action: LOW lets the
      person in, MEDIUM lets them in and logs it, HIGH asks for a one-time code, CRITICAL blocks and alerts the owner.
      The two models look at different things: the takeover model at this account's own history, the attack-IP model
      at how the IP behaves across all accounts.</p></details>
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
  const { news, videos, as_of } = await api("/v1/intel/news");
  stamp("news", as_of, ". Fetched live from the feeds, at most 30 minutes old.");
  $("#news-list").innerHTML = news.map((n) => `<li><a href="${esc(n.url)}" target="_blank" rel="noopener">${esc(n.title)}</a>
    <small>${esc(n.source)} · ${ago(n.published)}</small></li>`).join("") || '<li class="muted">Headlines are refreshing. Check back in a few minutes.</li>';
  $("#video-list").innerHTML = videos.map((v) => {
    const id = new URL(v.url).searchParams.get("v");
    return `<li class="vid">${id ? `<img src="https://i.ytimg.com/vi/${esc(id)}/mqdefault.jpg" alt="" loading="lazy">` : "<span></span>"}
      <div><a href="${esc(v.url)}" target="_blank" rel="noopener">${esc(v.title)}</a><small>${esc(v.source)} · ${ago(v.published)}</small></div></li>`;
  }).join("");
  $("#video-list").closest(".panel").hidden = !videos.length; // no videos: hide the panel rather than show an error
};

// ---------- data & accuracy ----------
const SPAN = { h: "hour", d: "day" };
const every = (span) => { const n = +span.slice(0, -1), u = SPAN[span.at(-1)]; return n === 1 ? `every ${u}` : `every ${n} ${u}s`; };
const spanMs = (span) => +span.slice(0, -1) * (span.endsWith("h") ? 3600e3 : 86400e3);

loaders.results = async () => {
  const [m, fr, src] = await Promise.all([api("/v1/model"), api("/v1/intel/freshness"), api("/v1/intel/sources")]);
  stamp("results", fr.snapshot, ". Snapshot of all threat data; the models were trained on 2020 to 2021 data.");
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
headerStatus();
