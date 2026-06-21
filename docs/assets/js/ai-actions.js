/* SecureVibe docs — AI-consumable page actions.
 * Adds a small toolbar under each page title:
 *   • Copy page  — copies the page's text to the clipboard (paste into any LLM)
 *   • Open in Claude — opens claude.ai with a prompt that references this page
 * Hooks Material's `document$` observable so it survives instant navigation.
 */
(function () {
  function addActions() {
    var article = document.querySelector(".md-content__inner");
    if (!article) return;
    // Skip the landing page (hero) — it's marketing, not a doc to copy for an LLM.
    if (article.querySelector(".ss-hero")) return;
    var h1 = article.querySelector("h1");
    if (!h1 || article.querySelector(".ai-actions")) return;

    var bar = document.createElement("div");
    bar.className = "ai-actions";

    var copy = document.createElement("button");
    copy.type = "button";
    copy.className = "ai-action";
    copy.textContent = "📋 Copy page";
    copy.addEventListener("click", function () {
      var text = article.innerText || "";
      navigator.clipboard.writeText(text).then(function () {
        copy.textContent = "✓ Copied";
        setTimeout(function () { copy.textContent = "📋 Copy page"; }, 1500);
      });
    });

    var ask = document.createElement("a");
    ask.className = "ai-action";
    ask.target = "_blank";
    ask.rel = "noopener";
    var prompt = "I'm reading this SecureVibe documentation page: " + location.href +
      "\n\nUsing it as context, help me with:";
    ask.href = "https://claude.ai/new?q=" + encodeURIComponent(prompt);
    ask.textContent = "🤖 Open in Claude";

    bar.appendChild(copy);
    bar.appendChild(ask);
    h1.insertAdjacentElement("afterend", bar);
  }

  if (typeof document$ !== "undefined" && document$.subscribe) {
    document$.subscribe(addActions); // Material instant navigation
  } else {
    document.addEventListener("DOMContentLoaded", addActions);
  }
})();
