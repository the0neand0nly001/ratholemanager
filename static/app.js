"use strict";

const byId = (identifier) => document.getElementById(identifier);
const previewMode = document.querySelector('meta[name="preview-mode"]').content === "true";
const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
let overview = null;
let activePage = "dashboard";
let previewId = null;
let confirmedAction = null;
let refreshing = false;

const pageDetails = {
    dashboard: "System dashboard",
    tunnels: "Tunnels",
    hosts: "Hosts",
    logs: "Service logs",
    activity: "Activity",
    settings: "Settings",
};

function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

function badge(text, kind = "") {
    const node = element("span", "badge " + kind);
    node.append(element("span", "dot " + (kind === "active" ? "green" : kind === "preview" ? "rose" : "")));
    node.append(document.createTextNode(text));
    return node;
}

async function api(path, method = "GET", body) {
    const response = await fetch(path, {
        method,
        headers: {"Content-Type": "application/json", "X-CSRFToken": csrfToken},
        ...(body === undefined ? {} : {body: JSON.stringify(body)}),
    });
    let data;
    try {
        data = await response.json();
    } catch {
        throw new Error("The server returned an unexpected response. Refresh and try again.");
    }
    if (!response.ok) {
        if (response.status === 401) window.location.assign("/login");
        throw new Error(data.error || "The request could not be completed.");
    }
    return data;
}

function notice(message, error = false) {
    byId("notice").textContent = message;
    byId("notice").className = "message" + (error ? " error" : "");
    byId("notice").hidden = false;
}

async function task(button, work) {
    const wasDisabled = button?.disabled;
    if (button) {
        button.disabled = true;
        button.setAttribute("aria-busy", "true");
    }
    try {
        return await work();
    } catch (error) {
        notice(error.message, true);
    } finally {
        if (button) {
            button.disabled = Boolean(wasDisabled);
            button.removeAttribute("aria-busy");
        }
    }
}

function openPage(page) {
    if (!pageDetails[page]) return;
    activePage = page;
    for (const [name] of Object.entries(pageDetails)) {
        byId("page-" + name).hidden = name !== page;
    }
    document.querySelectorAll(".nav-link[data-page]").forEach((button) => {
        button.classList.toggle("active", button.dataset.page === page);
        if (button.dataset.page === page) button.setAttribute("aria-current", "page");
        else button.removeAttribute("aria-current");
    });
    byId("pageTitle").textContent = pageDetails[page];
    byId("breadcrumbPage").textContent = page[0].toUpperCase() + page.slice(1);
    document.title = byId("breadcrumbPage").textContent + " · Rathole Manager";
    byId("addTunnelButton").hidden = !["dashboard", "tunnels"].includes(page);
    byId("sidebar").classList.remove("open");
    byId("sidebarOverlay").hidden = true;
    if (page === "logs") task(null, loadLogs);
    if (page === "activity") task(null, loadActivity);
    if (page === "settings") task(null, loadSettings);
}

function memoryLabel(status) {
    if (!status.memory_total) return "—";
    const used = (status.memory_total - status.memory_available) / 1024 / 1024;
    return Math.round(used) + " / " + Math.round(status.memory_total / 1024 / 1024) + " MB";
}

function hostTable(detailed = false) {
    const container = element("div", "table-scroll");
    const table = element("table", "host-table");
    const head = element("thead");
    const headings = element("tr");
    for (const name of ["Host", "Role", "Service", "State", "Memory", "Actions"]) headings.append(element("th", "", name));
    head.append(headings);
    const body = element("tbody");
    for (const role of ["server", "client"]) {
        const status = overview.status[role];
        const row = element("tr");
        const host = element("td");
        host.append(element("strong", "host-table-name", status.name || (role === "server" ? "VPS relay" : "Local gateway")));
        host.append(element("small", "host-table-subtitle", status.hostname || status.name));
        const state = element("td");
        state.append(badge(status.state === "active" ? "Running" : status.state === "preview" ? "Not connected" : status.state, status.state === "active" ? "active" : status.state === "preview" ? "" : "problem"));
        const actions = element("td");
        const controls = element("div", "table-actions");
        const logs = element("button", "", "Logs");
        logs.dataset.logs = role;
        controls.append(logs);
        if (detailed) {
            const restart = element("button", "", "Restart");
            restart.dataset.restart = role;
            restart.disabled = previewMode || !status.reachable;
            restart.title = previewMode ? "Live actions are disabled in the local preview." : "Restart Rathole on this host";
            controls.append(restart);
        }
        actions.append(controls);
        row.append(host, element("td", "", role === "server" ? "Relay" : "Gateway"), element("td", "mono", status.service || (role === "server" ? "rathole-server" : "rathole-client")), state, element("td", "mono", memoryLabel(status)), actions);
        body.append(row);
    }
    table.append(head, body);
    container.append(table);
    return container;
}

function routeState(route) {
    if (!route.enabled) return badge("Disabled", "disabled");
    if (route.problems.length) return badge(route.problems[0], "problem");
    if (overview?.draft) return badge("Draft", "preview");
    if (previewMode) return badge("Configured");
    if (overview?.status.server.state !== "active" || overview?.status.client.state !== "active") return badge("Host unavailable", "problem");
    const port = Number(route.bind_addr.split(":").at(-1));
    const listening = overview.status.server.listeners.some((listener) => listener.protocol === route.protocol && listener.port === port);
    return badge(listening ? "Listening" : "No listener", listening ? "active" : "problem");
}

function renderRows(targetId, routes, compact = false) {
    const body = byId(targetId);
    body.replaceChildren();
    if (!routes.length) {
        const row = element("tr");
        const cell = element("td", "empty-state", "No tunnels match this view.");
        cell.colSpan = 6;
        row.append(cell);
        body.append(row);
        return;
    }
    for (const route of routes) {
        const row = element("tr");
        const nameCell = element("td");
        const name = element("span", "tunnel-name");
        name.append(document.createTextNode(route.name));
        nameCell.append(name);
        const protocolCell = element("td");
        protocolCell.append(element("span", "protocol " + route.protocol, route.protocol.toUpperCase()));
        const state = element("td");
        state.append(routeState(route));
        const actionsCell = element("td");
        const actions = element("div", "table-actions");
        const edit = element("button", "", "Edit");
        edit.dataset.edit = route.name;
        actions.append(edit);
        if (!compact) {
            const toggle = element("button", "", route.enabled ? "Disable" : "Enable");
            toggle.dataset.operation = route.enabled ? "disable" : "enable";
            toggle.dataset.name = route.name;
            const remove = element("button", "delete", "Delete");
            remove.dataset.operation = "delete";
            remove.dataset.name = route.name;
            actions.append(toggle, remove);
        }
        actionsCell.append(actions);
        row.append(nameCell, protocolCell, element("td", "mono", route.bind_addr || "—"), element("td", "mono", route.local_addr || "—"), state, actionsCell);
        body.append(row);
    }
}

function renderFiltered() {
    if (!overview) return;
    const query = byId("tunnelSearch").value.trim().toLowerCase();
    const protocol = byId("protocolFilter").value;
    const state = byId("stateFilter").value;
    const rows = overview.routes.filter((route) => {
        const matchesText = [route.name, route.bind_addr, route.local_addr].some((value) => value.toLowerCase().includes(query));
        const matchesState = state === "all" || (state === "enabled" && route.enabled) || (state === "disabled" && !route.enabled) || (state === "issues" && route.problems.length > 0);
        return matchesText && matchesState && (protocol === "all" || protocol === route.protocol);
    });
    renderRows("tunnelRows", rows);
    byId("filterCount").textContent = rows.length + " of " + overview.routes.length + " tunnels";
}

async function refresh() {
    if (refreshing) return;
    refreshing = true;
    try {
        overview = await api("/api/overview");
        const routes = overview.routes;
        byId("navTunnelCount").textContent = routes.length;
        byId("statTotal").textContent = routes.length;
        byId("statTcp").textContent = routes.filter((route) => route.protocol === "tcp").length;
        byId("statUdp").textContent = routes.filter((route) => route.protocol === "udp").length;
        byId("statEnabled").textContent = routes.filter((route) => route.enabled).length;
        byId("statDisabled").textContent = routes.filter((route) => !route.enabled).length;
        const connected = Object.values(overview.status).filter((host) => host.reachable && host.state !== "preview").length;
        byId("statHosts").textContent = previewMode ? "—" : connected;
        byId("connectionLabel").replaceChildren(element("span", "dot " + (previewMode ? "rose" : connected === 2 ? "green" : "")), document.createTextNode(previewMode ? "Imported configuration" : connected + " hosts reachable"));
        for (const target of ["dashboardHosts", "fullHosts"]) {
            byId(target).replaceChildren(hostTable(target === "fullHosts"));
        }
        byId("overviewCount").textContent = routes.length;
        renderRows("overviewRows", routes.slice(0, 6), true);
        renderFiltered();
        byId("draftBar").hidden = !overview.draft;
        byId("lastChecked").textContent = "Checked " + new Date().toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
    } finally {
        refreshing = false;
    }
}

function editTunnel(name) {
    const route = name ? overview.routes.find((item) => item.name === name) : null;
    byId("tunnelForm").reset();
    byId("originalName").value = route?.name || "";
    byId("tunnelName").value = route?.name || "";
    byId("tunnelProtocol").value = route?.protocol || "tcp";
    byId("tunnelBind").value = route?.bind_addr || "0.0.0.0:";
    byId("tunnelLocal").value = route?.local_addr || "";
    byId("tunnelDialogTitle").textContent = route ? "Edit " + route.name : "Add a tunnel";
    byId("tunnelError").hidden = true;
    byId("tunnelDialog").showModal();
}

async function showPreview() {
    const data = await api("/api/preview");
    previewId = data.id;
    byId("serverDiff").textContent = data.diffs.server || "No changes to this host.";
    byId("clientDiff").textContent = data.diffs.client || "No changes to this host.";
    byId("serverDiffState").textContent = data.affected_hosts.includes("server") ? "Configuration changes · restart required" : "Unchanged";
    byId("clientDiffState").textContent = data.affected_hosts.includes("client") ? "Configuration changes · restart required" : "Unchanged";
    byId("applyNotice").textContent = previewMode ? "You can review drafts here. Applying changes is disabled in this local design preview." : data.notice;
    byId("applyConfirmed").checked = false;
    byId("applyConfirmed").disabled = previewMode;
    byId("applyButton").disabled = true;
    byId("previewError").hidden = true;
    if (!byId("previewDialog").open) byId("previewDialog").showModal();
}

function confirm(title, message, action, label = "Confirm") {
    byId("confirmTitle").textContent = title;
    byId("confirmMessage").textContent = message;
    byId("confirmAction").textContent = label;
    confirmedAction = action;
    byId("confirmDialog").showModal();
}

async function loadLogs() {
    byId("logText").textContent = "Reading service journal…";
    try {
        byId("logText").textContent = (await api("/api/hosts/" + byId("logHost").value + "/logs")).text || "No recent log entries.";
    } catch (error) {
        byId("logText").textContent = error.message;
        throw error;
    }
}

async function loadActivity() {
    const data = await api("/api/activity");
    byId("activityList").replaceChildren();
    if (!data.events.length) byId("activityList").append(element("p", "empty-state", "Your workspace activity will appear here."));
    for (const event of data.events) {
        const row = element("div", "activity-row");
        const description = element("div");
        description.append(element("p", "", event.detail), element("small", "", event.action.replaceAll("_", " ").toLowerCase()));
        row.append(element("span", "dot " + (event.level === "info" ? "rose" : "")), description, element("small", "activity-time", new Date(event.created).toLocaleString([], {dateStyle: "short", timeStyle: "short"})));
        byId("activityList").append(row);
    }
}

async function loadSettings() {
    const data = await api("/api/settings");
    byId("discordEnabled").checked = data.discord_enabled;
    byId("discordWebhook").value = "";
    byId("webhookHint").textContent = data.webhook_configured ? "A webhook is saved. Leave blank to keep it." : "Your webhook stays on the server.";
    byId("oidcEnabled").checked = data.oidc_enabled;
    byId("oidcIssuer").value = data.issuer;
    byId("oidcClientId").value = data.client_id;
    byId("oidcClientSecret").value = "";
    byId("oidcEmails").value = data.allowed_emails;
    byId("oidcBaseUrl").textContent = data.base_url ? "Callback URL: " + data.base_url.replace(/\/$/, "") + "/auth/callback" : "Set the dashboard base URL in the installation settings before enabling Authentik.";
    byId("testDiscord").disabled = previewMode;
}

document.addEventListener("click", (event) => {
    const button = event.target.closest("button");
    if (!button) return;
    if (button.dataset.page) openPage(button.dataset.page);
    if (button.dataset.go) openPage(button.dataset.go);
    if (button.dataset.close) byId(button.dataset.close).close();
    if (button.dataset.edit) editTunnel(button.dataset.edit);
    if (button.dataset.logs) {
        byId("logHost").value = button.dataset.logs;
        openPage("logs");
    }
    if (button.dataset.restart) {
        const role = button.dataset.restart;
        confirm("Restart Rathole on " + (role === "server" ? "the VPS?" : "the local gateway?"), "This restarts the Rathole service on this host only. Existing connections through it may reconnect.", async () => {
            await api("/api/hosts/" + role + "/restart", "POST", {confirmed: true});
            notice("Rathole restarted. Refreshing host status…");
            await refresh();
        }, "Restart Rathole");
    }
    if (button.dataset.operation) {
        const work = async () => {
            await api("/api/tunnels", "POST", {operation: button.dataset.operation, name: button.dataset.name});
            await refresh();
            await showPreview();
        };
        if (button.dataset.operation === "delete") confirm("Delete " + button.dataset.name + "?", "This adds the removal to your draft. The live tunnel stays unchanged until you review and apply.", work, "Add removal to draft");
        else task(button, work);
    }
});

byId("mobileMenu").addEventListener("click", () => {byId("sidebar").classList.add("open"); byId("sidebarOverlay").hidden = false;});
byId("sidebarOverlay").addEventListener("click", () => {byId("sidebar").classList.remove("open"); byId("sidebarOverlay").hidden = true;});
byId("helpButton").addEventListener("click", () => byId("helpDialog").showModal());
byId("addTunnelButton").addEventListener("click", () => editTunnel(null));
byId("refreshButton").addEventListener("click", (event) => task(event.currentTarget, async () => {await refresh(); if (activePage === "logs") await loadLogs(); if (activePage === "activity") await loadActivity();}));
byId("previewButton").addEventListener("click", (event) => task(event.currentTarget, showPreview));
byId("tunnelSearch").addEventListener("input", renderFiltered);
byId("protocolFilter").addEventListener("change", renderFiltered);
byId("stateFilter").addEventListener("change", renderFiltered);
byId("logHost").addEventListener("change", () => task(null, loadLogs));
byId("loadLogs").addEventListener("click", (event) => task(event.currentTarget, loadLogs));
byId("applyConfirmed").addEventListener("change", () => {byId("applyButton").disabled = previewMode || !byId("applyConfirmed").checked;});
byId("discardDraft").addEventListener("click", () => confirm("Discard this draft?", "Your live configurations will stay as they are. All unapplied edits in this draft will be removed.", async () => {await api("/api/draft/discard", "POST", {}); await refresh(); notice("Draft discarded. Live configurations are unchanged.");}, "Discard draft"));
byId("confirmAction").addEventListener("click", (event) => task(event.currentTarget, async () => {const action = confirmedAction; byId("confirmDialog").close(); confirmedAction = null; if (action) await action();}));

byId("tunnelForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.submitter;
    button.disabled = true;
    try {
        await api("/api/tunnels", "POST", {operation: "save", create: !byId("originalName").value, original_name: byId("originalName").value, name: byId("tunnelName").value, protocol: byId("tunnelProtocol").value, bind_addr: byId("tunnelBind").value, local_addr: byId("tunnelLocal").value});
        byId("tunnelDialog").close();
        await refresh();
        await showPreview();
    } catch (error) {
        byId("tunnelError").textContent = error.message;
        byId("tunnelError").hidden = false;
    } finally {
        button.disabled = false;
    }
});

byId("applyButton").addEventListener("click", async () => {
    byId("applyButton").disabled = true;
    try {
        await api("/api/apply", "POST", {preview_id: previewId, confirmed: byId("applyConfirmed").checked});
        byId("previewDialog").close();
        notice("Reviewed changes applied. Both configurations were verified.");
        await refresh();
    } catch (error) {
        byId("previewError").textContent = error.message;
        byId("previewError").hidden = false;
    } finally {
        byId("applyButton").disabled = previewMode || !byId("applyConfirmed").checked;
    }
});

byId("settingsForm").addEventListener("submit", (event) => {
    event.preventDefault();
    task(event.submitter, async () => {
        await api("/api/settings", "POST", {discord_enabled: byId("discordEnabled").checked, webhook: byId("discordWebhook").value, oidc_enabled: byId("oidcEnabled").checked, issuer: byId("oidcIssuer").value, client_id: byId("oidcClientId").value, client_secret: byId("oidcClientSecret").value, allowed_emails: byId("oidcEmails").value});
        await loadSettings();
        notice("Settings saved.");
    });
});
byId("testDiscord").addEventListener("click", (event) => task(event.currentTarget, async () => {await api("/api/settings/test-discord", "POST", {}); notice("Test notification requested. Check Discord and Activity for the result.");}));

task(null, refresh);
setInterval(() => {if (!document.hidden) task(null, refresh);}, 30000);
