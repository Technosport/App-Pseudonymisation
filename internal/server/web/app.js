"use strict";
const $ = (id) => document.getElementById(id);
const H = { "X-Requested-With": "pseudonymisation" };
let setupMode = false, anon = false, editingId = null, all = [];

async function api(method, url, body) {
  const opt = { method, headers: { ...H } };
  if (body instanceof FormData) opt.body = body;
  else if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  const r = await fetch(url, opt);
  let data = {};
  try { data = await r.json(); } catch (_) {}
  if (r.status === 401 && url !== "/api/unlock" && url !== "/api/password") { showLogin(false); }
  if (!r.ok) { const e = new Error(data.error || "Erreur " + r.status); e.status = r.status; e.data = data; throw e; }
  return data;
}

function show(id, on) { $(id).classList.toggle("hidden", !on); }

function showLogin(setup, r) {
  setupMode = setup;
  show("login", true); show("app", false);
  $("loginHelp").textContent = setup
    ? "Première utilisation : choisissez un mot de passe (8 caractères minimum)."
    : "";
  show("pw2row", setup); show("pwWarn", setup); show("setupFields", setup);
  
  ["setupTitre", "setupNom", "setupPrenom", "setupEmail"].forEach(id => $(id).required = setup);

  if (!setup && r && (r.titre || r.expNom)) {
    const meta = $("metaDisplay");
    meta.classList.remove("hidden");
    let html = `<div style="font-size:1.15em; color:var(--fg); font-weight:600; margin-bottom:0.4rem;">${r.titre || "App de Pseudonymisation"}</div>`;
    if (r.expNom || r.expPrenom) html += `<div style="margin-bottom:0.15rem;">Responsable : ${r.expPrenom} ${r.expNom}</div>`;
    if (r.expEmail) html += `<div>Contact : <a href="mailto:${r.expEmail}" style="color:var(--accent); text-decoration:none;">${r.expEmail}</a></div>`;
    meta.innerHTML = html;
  } else {
    $("metaDisplay").classList.add("hidden");
  }
  $("loginBtn").textContent = setup ? "Créer la base" : "Ouvrir";
  $("pw").value = ""; $("pw2").value = ""; $("loginErr").textContent = "";
  $("pw").focus();
}

function notice(msg, bad) {
  const n = $("notice");
  n.textContent = msg; n.classList.toggle("bad", !!bad); show("notice", !!msg);
}

$("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("loginErr").textContent = "";
  if (setupMode && $("pw").value !== $("pw2").value) { $("loginErr").textContent = "Les mots de passe ne correspondent pas."; return; }
  $("loginBtn").disabled = true;
  try {
    const payload = { password: $("pw").value };
    if (setupMode) {
      payload.titre = $("setupTitre").value;
      payload.expNom = $("setupNom").value;
      payload.expPrenom = $("setupPrenom").value;
      payload.expEmail = $("setupEmail").value;
    }
    const r = await api("POST", setupMode ? "/api/setup" : "/api/unlock", payload);
    $("pw").value = ""; $("pw2").value = "";
    await enterApp();
    if (r.warning) notice(r.warning, true);
  } catch (err) { $("loginErr").textContent = err.message; }
  finally { $("loginBtn").disabled = false; }
});

const FULL = [["n","N°"],["id","ID"],["dateAjout","Ajouté le"],["nom","Nom"],["prenom","Prénom"],["dateNaissance","Naissance"],["sexe","Sexe"],["taille","Taille"],["poids","Poids"],["telephone","Téléphone"],["email","E-mail"],["codeManip","Code Manip"]];
const ANON = ["n","id","dateAjout","sexe","taille","poids","codeManip"];
const cols = () => FULL.filter(([k]) => !anon || ANON.includes(k));

function fmtDate(s) { return /^\d{4}-\d{2}-\d{2}$/.test(s || "") ? s.split("-").reverse().join("/") : (s || ""); }

function td(text, cls) { const c = document.createElement("td"); c.textContent = text; if (cls) c.className = cls; return c; }

function render(list, total) {
  const head = $("thead"); head.replaceChildren();
  cols().forEach(([k, label]) => { const th = document.createElement("th"); th.textContent = label; if (k === "n") th.className = "n"; head.appendChild(th); });
  if (!anon) head.appendChild(document.createElement("th"));
  const body = $("rows"); body.replaceChildren();
  for (const p of list) {
    const tr = document.createElement("tr");
    cols().forEach(([k]) => tr.appendChild(td(k === "dateNaissance" || k === "dateAjout" ? fmtDate(p[k]) : p[k], k === "id" ? "id" : k === "n" ? "n" : "")));
    if (!anon) {
      const a = td("", "act");
      const e = document.createElement("button"); e.textContent = "Modifier"; e.onclick = () => openForm(p);
      const d = document.createElement("button"); d.textContent = "Supprimer"; d.className = "danger"; d.onclick = () => del(p);
      a.append(e, " ", d); tr.appendChild(a);
    }
    body.appendChild(tr);
  }
  $("count").textContent = list.length === total ? `(${total})` : `(${list.length} / ${total})`;
  show("empty", list.length === 0);
}

async function refresh() {
  const r = await api("GET", "/api/participants?q=" + encodeURIComponent($("search").value));
  all = r.participants; render(r.participants, r.total);
}

async function enterApp() {
  show("login", false); show("app", true); notice("");
  try {
    const r = await fetch("/api/state").then((x) => x.json());
    if (r.titre) {
      const h1 = document.querySelector("header h1");
      if (h1) h1.innerHTML = r.titre + ' <small id="count"></small>';
      document.title = r.titre + ' - Participants';
    }
  } catch(e) {}
  await refresh();
  checkUpdate();
}

async function checkUpdate() {
  try {
    const r = await api("GET", "/api/update/check");
    if (r.available && r.info) {
      $("updateBtn").classList.remove("hidden");
      $("updateBtn").textContent = `Mise à jour disponible (${r.info.tag_name})`;
      $("updateBtn").onclick = () => {
        $("updateTitle").textContent = `Mise à jour ${r.info.tag_name}`;
        $("updateNotes").textContent = r.info.body || "Améliorations diverses et corrections de bugs.";
        $("updateProgress").classList.add("hidden");
        $("updateError").classList.add("hidden");
        $("updateActions").classList.remove("hidden");
        $("doUpdateBtn").onclick = () => doUpdate(r.info);
        $("updateLaterBtn").onclick = () => $("updateDialog").close();
        $("updateDialog").showModal();
      };
    }
  } catch(e) { console.error("Erreur màj:", e); }
}

async function doUpdate(info) {
  const asset = info.assets.find(a => a.name.toLowerCase().endsWith(".zip"));
  if (!asset) {
    $("updateError").textContent = "Fichier d'installation non trouvé.";
    $("updateError").classList.remove("hidden");
    return;
  }
  $("updateActions").classList.add("hidden");
  $("updateProgress").classList.remove("hidden");
  $("updateError").classList.add("hidden");

  try {
    const r = await api("POST", "/api/update/apply", { url: asset.browser_download_url });
    if (r.ok) {
      document.body.innerHTML = "<div style='padding:2rem;text-align:center;'><h2>Mise à jour terminée avec succès !</h2><p>L'application a été fermée. Vous pouvez fermer cet onglet et relancer l'exécutable depuis votre clé USB.</p></div>";
    }
  } catch (err) {
    $("updateError").textContent = err.message || "La mise à jour a échoué.";
    $("updateError").classList.remove("hidden");
    $("updateActions").classList.remove("hidden");
    $("updateProgress").classList.add("hidden");
  }
}

let t;
$("search").addEventListener("input", () => { clearTimeout(t); t = setTimeout(() => refresh().catch(() => {}), 200); });

function openForm(p) {
  editingId = p ? p.id : null;
  $("formTitle").textContent = p ? `Modifier le participant ${p.id}` : "Nouveau participant";
  const f = $("pForm"); f.reset();
  for (const el of f.elements) if (el.name && p && p[el.name] !== undefined) el.value = p[el.name];
  $("formErr").textContent = "";
  $("formDlg").showModal();
}

$("addBtn").onclick = () => openForm(null);
$("cancelBtn").onclick = () => $("formDlg").close();

$("pForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = $("pForm");
  const body = {};
  for (const el of f.elements) if (el.name) body[el.name] = el.value;
  $("formErr").textContent = "";
  const url = editingId ? "/api/participants/" + encodeURIComponent(editingId) : "/api/participants";
  const method = editingId ? "PUT" : "POST";
  try {
    let saved;
    try { saved = await api(method, url, body); }
    catch (err) {
      if (err.status !== 409 || !err.data.duplicates) throw err;
      if (!confirm(`${err.message} (ID : ${err.data.duplicates.join(", ")}).\n\nEnregistrer quand même ?`)) return;
      saved = await api(method, url, { ...body, force: true });
    }
    $("formDlg").close();
    await refresh();
    if (!editingId) window.scrollTo(0, document.body.scrollHeight);
    notice(editingId ? "Participant modifié." : `Participant enregistré. ID : ${saved.id}`);
  } catch (err) { $("formErr").textContent = err.message; }
});

async function del(p) {
  if (!confirm(`Supprimer définitivement ${p.prenom} ${p.nom} (ID ${p.id}) ?\n\nLes sauvegardes existantes conservent une copie chiffrée.`)) return;
  try { await api("DELETE", "/api/participants/" + encodeURIComponent(p.id)); await refresh(); notice("Participant supprimé."); }
  catch (err) { notice(err.message, true); }
}

$("importBtn").onclick = () => $("file").click();
$("file").addEventListener("change", async () => {
  const file = $("file").files[0]; $("file").value = "";
  if (!file) return;
  const fd = new FormData(); fd.append("file", file);
  try {
    const r = await api("POST", "/api/import", fd);
    let msg = `Import terminé : ${r.added} ajouté(s), ${r.duplicates} doublon(s) ignoré(s).`;
    if (r.samePerson) msg += `\n${r.samePerson} personne(s) déjà présente(s) importée(s) avec leur ID d'origine (ID différent).`;
    if (r.newIds) msg += `\n${r.newIds} nouvel(le)s ID générés (ID absent ou déjà utilisé).`;
    if (r.errors.length) msg += `\n${r.errors.length} ligne(s) refusée(s) :\n` + r.errors.slice(0, 15).join("\n") + (r.errors.length > 15 ? "\n…" : "");
    await refresh(); notice(msg, r.errors.length > 0);
  } catch (err) { notice(err.message, true); }
});

$("backupBtn").onclick = async () => {
  closeMenus();
  try { const r = await api("POST", "/api/backup"); notice("Sauvegarde créée : " + r.file); } catch (err) { notice(err.message, true); }
};

$("anonBtn").onclick = () => { anon = !anon; $("anonState").textContent = anon ? "oui" : "non"; closeMenus(); render(all, all.length); refresh(); };

$("pwBtn").onclick = () => { closeMenus(); $("pwForm").reset(); $("pwErr").textContent = ""; $("pwDlg").showModal(); };
$("pwCancel").onclick = () => $("pwDlg").close();
$("pwForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("POST", "/api/password", { old: $("oldPw").value, new: $("newPw").value });
    $("pwDlg").close();
    notice("Mot de passe modifié. Les anciennes sauvegardes restent ouvrables avec l'ancien mot de passe.");
  } catch (err) { $("pwErr").textContent = err.message; }
});

$("auditBtn").onclick = async () => {
  closeMenus();
  try {
    const r = await api("GET", "/api/audit");
    const b = $("auditRows"); b.replaceChildren();
    for (const a of r.entries) {
      const tr = document.createElement("tr");
      tr.append(td(a.time.replace("T", " ").slice(0, 19)), td(a.action), td(a.id || "", "id"), td(a.detail || ""));
      b.appendChild(tr);
    }
    $("auditDlg").showModal();
  } catch (err) { notice(err.message, true); }
};
$("auditClose").onclick = () => $("auditDlg").close();

document.querySelectorAll("button.eye").forEach((b) => b.addEventListener("click", () => {
  const i = $(b.dataset.target);
  const show = i.type === "password";
  i.type = show ? "text" : "password";
  b.setAttribute("aria-label", show ? "Masquer le mot de passe" : "Afficher le mot de passe");
  b.style.opacity = show ? "0.5" : "1";
  i.focus();
}));

function closeMenus() { document.querySelectorAll("details.menu").forEach((d) => d.open = false); }
document.addEventListener("click", (e) => { if (!e.target.closest("details.menu")) closeMenus(); });

$("quitBtn").onclick = async () => {
  if (!confirm("Quitter l'application ?")) return;
  try {
    const r = await api("POST", "/api/quit");
    document.body.textContent = r.warning || "L'application est fermée. Vous pouvez fermer cet onglet et retirer la clé en toute sécurité.";
    document.body.style.padding = "2rem";
  } catch (err) { notice(err.message, true); }
};

setInterval(() => fetch("/api/ping").catch(() => {}), 15000);

(async function init() {
  try {
    const r = await fetch("/api/state").then((x) => x.json());
    if (r.state === "unlocked") await enterApp(); else showLogin(r.state === "setup", r);
  } catch (_) { document.body.textContent = "L'application ne répond pas. Relancez-la."; }
})();
