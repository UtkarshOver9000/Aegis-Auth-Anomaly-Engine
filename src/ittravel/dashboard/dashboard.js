document.addEventListener("DOMContentLoaded", () => {
  initChart();
  bindConsoleEvents();
});

function initChart() {
  const ctx = document.getElementById('riskChart').getContext('2d');
  
  // Gradient for area chart
  const gradient = ctx.createLinearGradient(0, 0, 0, 300);
  gradient.addColorStop(0, 'rgba(59, 130, 246, 0.4)');
  gradient.addColorStop(1, 'rgba(59, 130, 246, 0.0)');

  new Chart(ctx, {
    type: 'line',
    data: {
      labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', 'Now'],
      datasets: [{
        label: 'Anomaly Events',
        data: [12, 19, 15, 45, 22, 14, 5],
        borderColor: '#3B82F6',
        backgroundColor: gradient,
        borderWidth: 2,
        tension: 0.4,
        fill: true,
        pointBackgroundColor: '#1F2937',
        pointBorderColor: '#3B82F6',
        pointBorderWidth: 2,
        pointRadius: 4,
        pointHoverRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#9CA3AF' } },
        y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#9CA3AF' }, beginAtZero: true }
      }
    }
  });
}

function bindConsoleEvents() {
  const btnSimulate = document.getElementById('btn-simulate');
  const btnJump = document.getElementById('btn-jump');
  const output = document.getElementById('json-output');

  const execute = async () => {
    btnSimulate.innerHTML = '<span class="animate-pulse">Analyzing...</span>';
    
    const payload = {
      user_id: document.getElementById('inp-user').value,
      login_ts: new Date().toISOString(),
      lat: parseFloat(document.getElementById('inp-lat').value),
      lon: parseFloat(document.getElementById('inp-lon').value),
      city: "Unknown",
      country: "US",
      device_id: document.getElementById('inp-device').value,
      ip: document.getElementById('inp-ip').value
    };

    try {
      const res = await fetch('/v1/auth/evaluate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': 'demo-master-key-9000'
        },
        body: JSON.stringify(payload)
      });
      
      const data = await res.json();
      
      // Syntax highlight JSON output
      const jsonStr = JSON.stringify(data, null, 2);
      let colored = jsonStr.replace(/"is_anomaly": true/g, '<span class="text-red-400">"is_anomaly": true</span>');
      colored = colored.replace(/"risk_tier": "CRITICAL"/g, '<span class="text-red-500 font-bold">"risk_tier": "CRITICAL"</span>');
      colored = colored.replace(/"risk_score": ([\d.]+)/g, (match, p1) => {
        const score = parseFloat(p1);
        if (score > 60) return `<span class="text-red-400">"risk_score": ${p1}</span>`;
        return `"risk_score": ${p1}`;
      });

      output.innerHTML = colored;
      
      if (data.is_anomaly) {
        addAlertToFeed(data);
      }
    } catch (e) {
      output.innerText = `// Error connecting to Engine: ${e.message}`;
    }
    
    btnSimulate.innerText = 'Execute Payload';
  };

  btnSimulate.addEventListener('click', execute);

  btnJump.addEventListener('click', () => {
    // Inject impossible travel params
    document.getElementById('inp-lat').value = '35.6762';
    document.getElementById('inp-lon').value = '139.6503';
    document.getElementById('inp-ip').value = '203.0.113.10';
    document.getElementById('inp-device').value = 'dev_win11_unknown';
    execute();
  });
}

function addAlertToFeed(data) {
  const feed = document.getElementById('live-alerts');
  const alert = document.createElement('div');
  const color = data.risk_tier === 'CRITICAL' ? 'red' : 'yellow';
  
  alert.className = `p-3 bg-${color}-500/10 border border-${color}-500/20 rounded-lg animate-pulse`;
  alert.innerHTML = `
    <div class="flex justify-between items-start mb-1">
      <span class="text-xs font-semibold text-${color}-400">${data.risk_tier} • ${data.risk_score.toFixed(1)}</span>
      <span class="text-xs text-gray-500 code-font">Just now</span>
    </div>
    <div class="text-sm text-gray-200">${data.user_id} - ${data.reasons[0] || 'Anomalous login'}</div>
  `;
  
  feed.insertBefore(alert, feed.firstChild);
  setTimeout(() => alert.classList.remove('animate-pulse'), 2000);
}
