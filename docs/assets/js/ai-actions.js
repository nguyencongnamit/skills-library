/* SecureVibe docs — AI-consumable page actions.
 * Adds a small toolbar under each page title:
 *   • Copy page  — copies the page's text to the clipboard (paste into any LLM)
 *   • Open in Claude — opens claude.ai with a prompt that references this page
 *   • Open in Codex — opens ChatGPT/Codex with the same prompt
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

    var prompt = "I'm reading this SecureVibe documentation page: " + location.href +
      "\n\nUsing it as context, help me with:";
    var encoded = encodeURIComponent(prompt);

    var ask = document.createElement("a");
    ask.className = "ai-action";
    ask.target = "_blank";
    ask.rel = "noopener";
    ask.href = "https://claude.ai/new?q=" + encoded;
    ask.textContent = "🤖 Open in Claude";

    var codex = document.createElement("a");
    codex.className = "ai-action";
    codex.target = "_blank";
    codex.rel = "noopener";
    codex.href = "https://chatgpt.com/?q=" + encoded;
    codex.textContent = "⚡ Open in Codex";

    bar.appendChild(copy);
    bar.appendChild(ask);
    bar.appendChild(codex);
    h1.insertAdjacentElement("afterend", bar);
  }

  if (typeof document$ !== "undefined" && document$.subscribe) {
    document$.subscribe(addActions); // Material instant navigation
  } else {
    document.addEventListener("DOMContentLoaded", addActions);
  }
})();
