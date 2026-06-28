(() => {
  const initMermaid = async () => {
    if (!window.mermaid) {
      return;
    }

    const styles = getComputedStyle(document.documentElement);
    const value = (name) => styles.getPropertyValue(name).trim();

    window.mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      theme: "base",
      fontFamily: value("--font-sans"),
      themeVariables: {
        fontFamily: value("--font-sans"),
        background: value("--ds-bg-elevated"),
        mainBkg: value("--ds-bg-elevated"),
        primaryColor: value("--ob-color-bao-1"),
        primaryTextColor: value("--ds-text"),
        primaryBorderColor: value("--ob-color-brand"),
        secondaryColor: value("--ds-bg-subtle"),
        secondaryTextColor: value("--ds-text"),
        secondaryBorderColor: value("--ob-color-brand-soft"),
        tertiaryColor: value("--ds-bg"),
        tertiaryTextColor: value("--ds-text"),
        tertiaryBorderColor: value("--ds-border-strong"),
        lineColor: value("--ob-color-brand"),
        textColor: value("--ds-text"),
        actorBkg: value("--ds-bg-elevated"),
        actorBorder: value("--ob-color-brand"),
        actorTextColor: value("--ds-text"),
        noteBkgColor: value("--ob-color-bao-1"),
        noteBorderColor: value("--ob-color-brand"),
        noteTextColor: value("--ds-text"),
        clusterBkg: value("--ds-bg-subtle"),
        clusterBorder: value("--ob-color-brand"),
        labelBoxBkgColor: value("--ds-bg-elevated"),
        labelBoxBorderColor: value("--ob-color-brand"),
        labelTextColor: value("--ds-text"),
        signalColor: value("--ob-color-brand"),
        cScale0: value("--ob-color-bao-1"),
        cScale1: value("--ob-color-bao-2"),
        cScale2: value("--ob-color-brand-soft"),
        cScaleLabel0: value("--ds-text"),
        cScaleLabel1: value("--ds-text"),
        cScaleLabel2: value("--ds-text")
      },
      flowchart: {
        htmlLabels: true,
        curve: "basis",
        useMaxWidth: true
      },
      sequence: {
        useMaxWidth: true,
        wrap: true
      }
    });

    const diagrams = Array.from(document.querySelectorAll(".mermaid"));
    for (const diagram of diagrams) {
      try {
        await window.mermaid.run({
          nodes: [diagram]
        });
      } catch (error) {
        diagram.dataset.mermaidError = "true";
        diagram.setAttribute("aria-label", "Diagram failed to render");
        console.error("Mermaid diagram failed to render", error);
      }
    }
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initMermaid, { once: true });
    return;
  }

  initMermaid();
})();
