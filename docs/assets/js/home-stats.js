// Populate the homepage curated-data numbers from the shipped datasets so they
// stay in sync with the data automatically — no hand-editing index.md on every
// curated-data refresh. The HTML keeps sensible fallback values for no-JS /
// pre-fetch; this script overwrites them once the JSON loads.
//
// Mirrors the client-side rendering already used by Coverage / Threat-Intel.
// Hooks Material's `document$` so it survives instant navigation.
document$.subscribe(function () {
  var statEcos = document.querySelector('[data-sv-stat="ecosystems"]');
  var statSkills = document.querySelector('[data-sv-stat="skills"]');
  var card = document.querySelector('[data-sv-card="supply"]');
  if (!statEcos && !statSkills && !card) return; // not the homepage

  function dataURL(p) { return new URL(p, document.baseURI).href; }

  fetch(dataURL("assets/data/malicious-packages.json"))
    .then(function (r) { return r.json(); })
    .then(function (d) {
      var entries = d.entries || [];
      var total = typeof d.count === "number" ? d.count : entries.length;
      var ecos = {};
      entries.forEach(function (e) { if (e.ecosystem) ecos[e.ecosystem] = 1; });
      var nEcos = Object.keys(ecos).length;
      var totalStr = total.toLocaleString("en-US");
      if (statEcos) statEcos.textContent = String(nEcos);
      if (card) {
        card.textContent =
          totalStr +
          " web-cited malicious-package entries across " +
          nEcos +
          " ecosystems + typosquats. Browse the curated canon →";
      }
    })
    .catch(function () { /* keep the static fallback */ });

  if (statSkills) {
    fetch(dataURL("assets/data/skills.json"))
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var n = (d.skills && d.skills.length) || d.count;
        if (n) statSkills.textContent = String(n);
      })
      .catch(function () { /* keep the static fallback */ });
  }
});
