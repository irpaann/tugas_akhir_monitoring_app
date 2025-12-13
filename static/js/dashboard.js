function loadLogs() {
    fetch("/api/logs")
        .then(res => res.json())
        .then(data => {
            const tbody = document.querySelector("#logTable tbody");
            tbody.innerHTML = "";

            data.logs.forEach(log => {
                const tr = document.createElement("tr");

                const threatColor =
                    log.threat_score >= 80 ? "danger" :
                    log.threat_score >= 50 ? "warning" : "success";

                const hasPayload = log.payload && log.payload.trim().length > 0;

                tr.innerHTML = `
                    <td>${log.id}</td>
                    <td>${log.timestamp}</td>
                    <td>${log.ip}</td>
                    <td>${log.method}</td>
                    <td>${log.status}</td>
                    <td>${log.path}</td>

                    <td>
                        <a href="${log.full_url}" target="_blank">${log.full_url}</a>
                    </td>

                    <td>
                        <span class="badge bg-info text-dark" data-bs-toggle="tooltip" title="${log.user_agent}">
                            UA
                        </span>
                    </td>

                    <td class="position-relative">
                        <button class="btn btn-sm btn-outline-primary position-relative"
                            onclick='showPayload(${JSON.stringify(log.payload).replace(/'/g, "&apos;")})'>
                            View
                        </button>

                        ${hasPayload ? `
                            <span class="position-absolute top-0 start-100 translate-middle p-1 bg-danger rounded-circle"
                                style="transform: translate(-85%, 35%);">
                            </span>` : ""}
                    </td>

                    <td>
                        <span class="badge bg-${threatColor}">
                            ${log.threat_score}
                        </span>
                    </td>
                `;



                tbody.appendChild(tr);
            });

            // aktifkan tooltip Bootstrap
            const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
            [...tooltipTriggerList].map(el => new bootstrap.Tooltip(el));
        });
}

setInterval(loadLogs, 3000);
loadLogs();


// ======================
// PAYLOAD POPUP MODAL
// ======================
function showPayload(payload) {
    const modalBody = document.getElementById("payloadModalBody");
    modalBody.textContent = payload || "(empty)";
    const modal = new bootstrap.Modal(document.getElementById("payloadModal"));
    modal.show();
}

setInterval(loadLogs, 3000);
loadLogs();


let chartRequests, chartMethods, chartStatus;

function loadCharts() {

    // ===== Requests per minute =====
    fetch("/api/stats/requests")
        .then(res => res.json())
        .then(data => {
            if (chartRequests) chartRequests.destroy();
            chartRequests = new Chart(document.getElementById("chartRequests"), {
                type: "line",
                data: {
                    labels: data.labels,
                    datasets: [{
                        label: "Requests",
                        data: data.values,
                        borderWidth: 2
                    }]
                }
            });
        });

    // ===== Methods =====
    fetch("/api/stats/methods")
        .then(res => res.json())
        .then(data => {
            if (chartMethods) chartMethods.destroy();
            chartMethods = new Chart(document.getElementById("chartMethods"), {
                type: "bar",
                data: {
                    labels: data.labels,
                    datasets: [{
                        label: "Total",
                        data: data.values,
                        borderWidth: 2
                    }]
                }
            });
        });

    // ===== Status Codes =====
    fetch("/api/stats/status")
        .then(res => res.json())
        .then(data => {
            if (chartStatus) chartStatus.destroy();
            chartStatus = new Chart(document.getElementById("chartStatus"), {
                type: "bar",
                data: {
                    labels: data.labels,
                    datasets: [{
                        label: "Count",
                        data: data.values,
                        borderWidth: 2
                    }]
                }
            });
        });
}

setInterval(loadCharts, 5000);
loadCharts();
