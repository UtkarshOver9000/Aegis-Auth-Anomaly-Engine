# After the globe changes (9 October 2026, local build)

Desktop keeps everything it had: the 4096 px NASA texture, all 4,596 state and province borders, country
borders, cables (on demand), hover and click per state, and chained sign-in journeys. What changed is
where the work happens. The server paints the states into the texture, so the browser no longer draws
them, and phones get a 2048 px texture.

| | Before (`../screens/desktop-globe.jpg`) | After (`desktop-globe.jpg`) |
|---|---|---|
| Texture | 4096 px, states painted in the browser | 4096 px, painted on the server |
| Colours | blue to red, continuous | 6 ColorBrewer YlOrRd classes with a legend, grey for no data |
| Malware and DNS | raw counts | per million IP addresses |
| Libraries on the home tab | d3, topojson, globe.gl, Leaflet (~2.3 MB) | none; they load with the tab that needs them |
