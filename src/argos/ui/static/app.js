const state = {
  investigations: [],
  currentId: null,
  detail: {
    investigation: null,
    artifacts: [],
    evidences: [],
    relations: [],
  },
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function showToast(msg, isError = false) {
  const el = $("#toast");
  el.textContent = msg;
  el.classList.toggle("error", isError);
  el.classList.remove("hidden");
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.add("hidden"), 3500);
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function epistemicBadge(status) {
  const s = String(status || "unverified").toLowerCase();
  return `<span class="pill ep-${escapeHtml(s)}">${escapeHtml(s)}</span>`;
}

async function loadHealth() {
  try {
    const info = await api("/api/health");
    $("#db-indicator").textContent = `SQLite: ${info.db_path}`;
    $("#db-indicator").title = info.db_path;
  } catch (err) {
    showToast(`Falha na conexão local: ${err.message}`, true);
  }
}

async function loadInvestigations(selectId = null) {
  const data = await api("/api/investigations");
  state.investigations = data.investigations || [];
  const select = $("#investigation-select");
  select.innerHTML = "";

  if (state.investigations.length === 0) {
    const opt = document.createElement("option");
    opt.value = "";
    opt.textContent = "Nenhuma investigação — crie uma";
    select.appendChild(opt);
    state.currentId = null;
    $("#modal-new-inv").showModal();
    return;
  }

  for (const inv of state.investigations) {
    const opt = document.createElement("option");
    opt.value = inv.id;
    opt.textContent = `${inv.title} [${inv.status || "open"}]`;
    select.appendChild(opt);
  }

  const targetId =
    selectId ||
    (state.investigations.some((i) => i.id === state.currentId)
      ? state.currentId
      : state.investigations[0].id);

  select.value = targetId;
  await selectInvestigation(targetId);
}

async function selectInvestigation(invId) {
  if (!invId) return;
  state.currentId = invId;
  const data = await api(`/api/investigations/${encodeURIComponent(invId)}`);
  state.detail = data;
  renderInvestigation();
}

function renderInvestigation() {
  const { investigation: inv, artifacts, evidences, relations } = state.detail;
  if (!inv) return;

  $("#inv-title").value = inv.title || "";
  $("#inv-status").value = inv.status || "open";
  $("#inv-status-badge").textContent = inv.status || "open";
  $("#inv-objective").value = inv.objective || "";
  $("#inv-scope").value = inv.scope || "";
  $("#inv-notes").value = Array.isArray(inv.notes) ? inv.notes.join("\n") : (inv.notes || "");
  $("#inv-conclusion").value = inv.conclusion || "";
  $("#inv-limitations").value = Array.isArray(inv.limitations)
    ? inv.limitations.join("\n")
    : (inv.limitations || "");

  $("#count-artifacts").textContent = artifacts.length;
  $("#count-evidences").textContent = evidences.length;
  $("#count-relations").textContent = relations.length;

  renderArtifactsTable();
  renderRelationsTable();
  renderEvidencesTable();
  populateSelectors();
  updateDownloadLinks();
}

function getArtifactEpistemicMap() {
  const map = new Map();
  for (const ev of state.detail.evidences) {
    if (ev.artifact_id && !map.has(ev.artifact_id)) {
      map.set(ev.artifact_id, ev.epistemic_status);
    }
  }
  return map;
}

function renderArtifactsTable() {
  const search = $("#filter-search").value.trim().toLowerCase();
  const typeFilter = $("#filter-type").value;
  const epFilter = $("#filter-epistemic").value;
  const epMap = getArtifactEpistemicMap();

  const filtered = state.detail.artifacts.filter((a) => {
    const ep = a.epistemic_status || epMap.get(a.id) || "unverified";
    if (typeFilter && a.artifact_type !== typeFilter) return false;
    if (epFilter && ep !== epFilter) return false;
    if (search) {
      const hay = `${a.value} ${a.original_value} ${a.source}`.toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  const tbody = $("#tbody-artifacts");
  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="muted">Nenhum artefato encontrado para os filtros atuais.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered
    .map((a) => {
      const ep = a.epistemic_status || epMap.get(a.id) || "unverified";
      return `<tr>
        <td><span class="pill">${escapeHtml(a.artifact_type)}</span></td>
        <td class="mono">${escapeHtml(a.value)}</td>
        <td class="mono muted">${escapeHtml(a.original_value)}</td>
        <td>${escapeHtml(a.source)}</td>
        <td>${epistemicBadge(ep)}</td>
        <td class="mono muted" title="${escapeHtml(a.id)}">${escapeHtml(String(a.id).slice(0, 12))}</td>
      </tr>`;
    })
    .join("");
}

function renderRelationsTable() {
  const byId = new Map(state.detail.artifacts.map((a) => [a.id, a]));
  const tbody = $("#tbody-relations");
  if (state.detail.relations.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="muted">Nenhuma relação registrada nesta investigação.</td></tr>`;
    return;
  }
  tbody.innerHTML = state.detail.relations
    .map((r) => {
      const src = byId.get(r.source_artifact_id)?.value || r.source_artifact_id;
      const dst = byId.get(r.target_artifact_id)?.value || r.target_artifact_id;
      return `<tr>
        <td class="mono">${escapeHtml(src)}</td>
        <td><span class="pill">${escapeHtml(r.relation_type)}</span></td>
        <td class="mono">${escapeHtml(dst)}</td>
        <td>${epistemicBadge(r.epistemic_status)}</td>
        <td>${escapeHtml(r.context || "—")}</td>
      </tr>`;
    })
    .join("");
}

function renderEvidencesTable() {
  const byId = new Map(state.detail.artifacts.map((a) => [a.id, a]));
  const tbody = $("#tbody-evidences");
  if (state.detail.evidences.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="muted">Nenhuma evidência registrada.</td></tr>`;
    return;
  }
  tbody.innerHTML = state.detail.evidences
    .map((e) => {
      const artLabel = e.artifact_id
        ? byId.get(e.artifact_id)?.value || String(e.artifact_id).slice(0, 12)
        : "—";
      return `<tr>
        <td>${escapeHtml(e.collection_method)}</td>
        <td>${epistemicBadge(e.epistemic_status)}</td>
        <td>${escapeHtml(e.source)}</td>
        <td class="mono muted" title="${escapeHtml(e.content_hash)}">${escapeHtml(String(e.content_hash || "").slice(0, 16))}…</td>
        <td class="mono">${escapeHtml(artLabel)}</td>
      </tr>`;
    })
    .join("");
}

function populateSelectors() {
  const options = state.detail.artifacts
    .map(
      (a) =>
        `<option value="${escapeHtml(a.id)}">[${escapeHtml(a.artifact_type)}] ${escapeHtml(a.value)}</option>`
    )
    .join("");

  $("#rel-source").innerHTML = options || `<option value="">Sem artefatos</option>`;
  $("#rel-target").innerHTML = options || `<option value="">Sem artefatos</option>`;
  $("#pivot-artifact").innerHTML = options || `<option value="">Sem artefatos</option>`;

  const evOptions =
    `<option value="">Nenhuma</option>` +
    state.detail.evidences
      .map(
        (e) =>
          `<option value="${escapeHtml(e.id)}">${escapeHtml(e.collection_method)} (${escapeHtml(e.source)})</option>`
      )
      .join("");
  $("#rel-evidence").innerHTML = evOptions;
}

function updateDownloadLinks() {
  if (!state.currentId) return;
  const base = `/api/investigations/${encodeURIComponent(state.currentId)}`;
  $("#link-dl-md").href = `${base}/report?format=markdown&download=1`;
  $("#link-dl-json").href = `${base}/report?format=json&download=1`;
  $("#link-dl-csv").href = `${base}/export?format=csv&download=1`;
  $("#link-dl-stix").href = `${base}/export?format=stix&download=1`;
}

function showCollectionSummary(result) {
  const box = $("#collect-summary");
  const summary = {
    created_artifacts: (result.created_artifacts || []).length,
    created_evidences: (result.created_evidences || []).length,
    created_relations: (result.created_relations || []).length,
    skipped_indicators: (result.skipped_indicators || []).length,
    errors: result.errors || [],
  };
  box.textContent = JSON.stringify(summary, null, 2);
  box.classList.remove("hidden");
}

function renderPivotResult(pivot) {
  const container = $("#pivot-output");
  const stoppedBanner = pivot.stopped_by_limit
    ? `<div class="hop-card" style="border-color: var(--warn)"><strong>Parada por limite alcançado (stopped_by_limit = true)</strong>: ajuste <code>max_depth</code> ou <code>max_steps</code> com cautela analítica.</div>`
    : `<div class="hop-card"><strong>Exploração concluída dentro dos limites</strong> (<code>stopped_by_limit = false</code>).</div>`;

  const hops = pivot.hops || pivot.steps || [];
  if (hops.length === 0) {
    container.innerHTML = `${stoppedBanner}<p class="muted">Nenhum salto encontrado a partir deste artefato.</p>`;
    return;
  }

  const hopHtml = hops
    .map(
      (h, idx) =>
        `<div class="hop-card"><div class="muted">Salto #${idx + 1} (depth: ${escapeHtml(h.depth ?? idx + 1)})</div><pre class="mono" style="margin:0.35rem 0 0 0;white-space:pre-wrap">${escapeHtml(JSON.stringify(h, null, 2))}</pre></div>`
    )
    .join("");

  container.innerHTML = stoppedBanner + hopHtml;
}

function renderAssessment(assess) {
  const dimensions = [
    ["source_reliability", "Confiabilidade da Fonte"],
    ["evidence_quality", "Qualidade da Evidência"],
    ["confidence", "Confiança Analítica"],
    ["indicator_validity", "Validade dos Indicadores"],
    ["operational_relevance", "Relevância Operacional"],
    ["risk", "Risco Contextual"],
  ];

  const cards = dimensions
    .map(([key, label]) => {
      const val = assess[key];
      const formatted = typeof val === "object" ? JSON.stringify(val, null, 2) : String(val ?? "—");
      return `<div class="assess-card"><h4>${escapeHtml(label)} (${escapeHtml(key)})</h4><pre style="margin:0;white-space:pre-wrap;font-family:inherit">${escapeHtml(formatted)}</pre></div>`;
    })
    .join("");

  const gaps = Array.isArray(assess.gaps) ? assess.gaps : [];
  const limitations = Array.isArray(assess.limitations)
    ? assess.limitations
    : assess.limitations
      ? [assess.limitations]
      : [];

  const listBlock = (title, items) =>
    `<div class="assess-card"><h4>${escapeHtml(title)}</h4>${
      items.length
        ? `<ul>${items.map((i) => `<li>${escapeHtml(typeof i === "object" ? JSON.stringify(i) : i)}</li>`).join("")}</ul>`
        : `<p class="muted">Nenhum item apontado.</p>`
    }</div>`;

  $("#assessment-output").innerHTML =
    cards + listBlock("Lacunas (Gaps)", gaps) + listBlock("Limitações", limitations);
}

function bindEvents() {
  $$(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$(".tab").forEach((b) => b.classList.remove("active"));
      $$(".tab-pane").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      $(`#tab-${btn.dataset.tab}`).classList.add("active");
    });
  });

  $$(".subtab").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$(".subtab").forEach((b) => b.classList.remove("active"));
      $$(".collect-form").forEach((f) => f.classList.add("hidden"));
      btn.classList.add("active");
      $(`#form-collect-${btn.dataset.collectMode}`).classList.remove("hidden");
    });
  });

  $("#investigation-select").addEventListener("change", (e) => selectInvestigation(e.target.value));
  $("#btn-new-inv-modal").addEventListener("click", () => $("#modal-new-inv").showModal());
  $("#btn-close-modal").addEventListener("click", () => $("#modal-new-inv").close());
  $("#btn-cancel-modal").addEventListener("click", () => $("#modal-new-inv").close());

  $("#form-new-inv").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const res = await api("/api/investigations", {
        method: "POST",
        body: JSON.stringify({
          title: $("#new-inv-title").value,
          objective: $("#new-inv-objective").value,
          scope: $("#new-inv-scope").value,
        }),
      });
      e.target.reset();
      $("#modal-new-inv").close();
      showToast("Investigação criada.");
      await loadInvestigations(res.investigation.id);
    } catch (err) {
      showToast(err.message, true);
    }
  });

  $("#form-update-inv").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!state.currentId) return;
    try {
      await api(`/api/investigations/${encodeURIComponent(state.currentId)}`, {
        method: "PATCH",
        body: JSON.stringify({
          title: $("#inv-title").value,
          status: $("#inv-status").value,
          objective: $("#inv-objective").value,
          scope: $("#inv-scope").value,
          notes: $("#inv-notes").value,
          conclusion: $("#inv-conclusion").value,
          limitations: $("#inv-limitations").value,
        }),
      });
      showToast("Metadados atualizados.");
      await loadInvestigations(state.currentId);
    } catch (err) {
      showToast(err.message, true);
    }
  });

  $("#form-collect-text").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!state.currentId) return;
    try {
      const res = await api(`/api/investigations/${encodeURIComponent(state.currentId)}/collect-text`, {
        method: "POST",
        body: JSON.stringify({
          text: $("#collect-text-input").value,
          source: $("#collect-text-source").value,
          epistemic_status: $("#collect-text-status").value,
        }),
      });
      showCollectionSummary(res.result);
      $("#collect-text-input").value = "";
      showToast("Indicadores processados.");
      await selectInvestigation(state.currentId);
    } catch (err) {
      showToast(err.message, true);
    }
  });

  $("#form-collect-file").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!state.currentId) return;
    try {
      const picker = $("#collect-file-picker");
      const payload = {
        epistemic_status: $("#collect-file-status").value,
      };
      if (picker.files && picker.files.length > 0) {
        const file = picker.files[0];
        payload.file_name = file.name;
        payload.content = await file.text();
      } else {
        payload.file_path = $("#collect-file-path").value;
      }
      const res = await api(`/api/investigations/${encodeURIComponent(state.currentId)}/collect-file`, {
        method: "POST",
        body: JSON.stringify(payload),
      });
      showCollectionSummary(res.result);
      e.target.reset();
      showToast("Arquivo coletado.");
      await selectInvestigation(state.currentId);
    } catch (err) {
      showToast(err.message, true);
    }
  });

  $("#form-collect-feed").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!state.currentId) return;
    try {
      const res = await api(`/api/investigations/${encodeURIComponent(state.currentId)}/collect-feed`, {
        method: "POST",
        body: JSON.stringify({
          url: $("#collect-feed-url").value,
          source: $("#collect-feed-source").value,
          epistemic_status: $("#collect-feed-status").value,
        }),
      });
      showCollectionSummary(res.result);
      showToast("Feed coletado.");
      await selectInvestigation(state.currentId);
    } catch (err) {
      showToast(err.message, true);
    }
  });

  $("#filter-search").addEventListener("input", renderArtifactsTable);
  $("#filter-type").addEventListener("change", renderArtifactsTable);
  $("#filter-epistemic").addEventListener("change", renderArtifactsTable);

  $("#form-create-relation").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!state.currentId) return;
    try {
      await api(`/api/investigations/${encodeURIComponent(state.currentId)}/relations`, {
        method: "POST",
        body: JSON.stringify({
          source_artifact_id: $("#rel-source").value,
          relation_type: $("#rel-type").value,
          target_artifact_id: $("#rel-target").value,
          epistemic_status: $("#rel-epistemic").value,
          evidence_id: $("#rel-evidence").value || null,
          context: $("#rel-context").value,
        }),
      });
      $("#rel-context").value = "";
      showToast("Relação registrada.");
      await selectInvestigation(state.currentId);
    } catch (err) {
      showToast(err.message, true);
    }
  });

  $("#form-pivot").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!state.currentId) return;
    try {
      const res = await api(`/api/investigations/${encodeURIComponent(state.currentId)}/pivot`, {
        method: "POST",
        body: JSON.stringify({
          artifact_id: $("#pivot-artifact").value,
          max_depth: Number($("#pivot-depth").value),
          max_steps: Number($("#pivot-steps").value),
        }),
      });
      renderPivotResult(res.pivot);
    } catch (err) {
      showToast(err.message, true);
    }
  });

  $("#btn-run-assess").addEventListener("click", async () => {
    if (!state.currentId) return;
    try {
      const res = await api(`/api/investigations/${encodeURIComponent(state.currentId)}/assess`);
      renderAssessment(res.assessment);
      showToast("Avaliação analítica atualizada.");
    } catch (err) {
      showToast(err.message, true);
    }
  });

  const loadPreview = async (fmt) => {
    if (!state.currentId) return;
    try {
      const res = await api(
        `/api/investigations/${encodeURIComponent(state.currentId)}/report?format=${fmt}`
      );
      $("#report-preview").textContent = res.content;
    } catch (err) {
      showToast(err.message, true);
    }
  };

  $("#btn-preview-md").addEventListener("click", () => loadPreview("markdown"));
  $("#btn-preview-json").addEventListener("click", () => loadPreview("json"));
  $("#btn-copy-report").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("#report-preview").textContent);
      showToast("Conteúdo copiado para a área de transferência.");
    } catch {
      showToast("Não foi possível acessar a área de transferência.", true);
    }
  });
}


  const resetBtn = $("#btn-reset-db");
  if (resetBtn) {
    resetBtn.addEventListener("click", async () => {
      const confirmed = window.confirm(
        "Tem certeza que deseja apagar todas as investigações, artefatos, evidências e relações do banco SQLite atual?"
      );
      if (!confirmed) return;
      try {
        await api("/api/reset", { method: "POST", body: JSON.stringify({}) });
        state.currentId = null;
        state.detail = { investigation: null, artifacts: [], evidences: [], relations: [] };
        await loadInvestigations();
        showToast("Banco SQLite zerado com sucesso.");
      } catch (err) {
        showToast(`Falha ao zerar banco: ${err.message}`, true);
      }
    });
  }

document.addEventListener("DOMContentLoaded", async () => {
  bindEvents();
  await loadHealth();
  await loadInvestigations();
});
