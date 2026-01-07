// ======================
// UTIL FUNCTIONS
// ======================

function threatBadge(score) {
    if (score >= 70) return "bg-danger";
    if (score >= 40) return "bg-warning text-dark";
    return "bg-success";
}

function isSuspiciousPayload(payload) {
    if (!payload) return false;

    const patterns = [
        /or\s+1=1/i,
        /union\s+select/i,
        /<script.*?>/i,
        /--/,
        /\/\.\./,
        /sleep\(/i,
        /benchmark\(/i
    ];

    return patterns.some(p => p.test(payload));
}

function truncate(text, max = 40) {
    if (!text) return "";
    return text.length > max ? text.substring(0, max) + "..." : text;
}

// ======================
// LOAD LOGS
// ======================

function loadLogs() {
    const params = new URLSearchParams(getFilterParams());

    fetch("/api/logs?" + params.toString())
        .then(res => res.json())
        .then(data => {
            const tbody = document.querySelector("#logTable tbody");
            tbody.innerHTML = "";

            data.logs.forEach(log => {

                // 🔥 PENTING: harus DI SINI
                const suspicious = isSuspiciousPayload(log.payload);
                const preview = truncate(log.payload);

                const tr = document.createElement("tr");

                tr.innerHTML = `
                    <td>${log.id}</td>
                    <td>${log.timestamp}</td>
                    <td>${log.ip}</td>
                    <td>${log.method}</td>
                    <td>${log.status}</td>
                    <td>${log.path}</td>

                    <td>
                        <a href="${log.full_url}" target="_blank">
                            ${log.full_url}
                        </a>
                    </td>

                    <td>
                        <span class="badge bg-info text-dark"
                            style="cursor:pointer"
                            onclick='showUserAgent(${JSON.stringify(log.user_agent)})'>
                            UA
                        </span>
                    </td>

                    <td>
                        <span class="badge ${suspicious ? "bg-danger" : "bg-secondary"}"
                            style="cursor:pointer"
                            onclick='showPayload(${JSON.stringify(log.payload)})'>
                            ${preview || "empty"}
                        </span>
                    </td>

                    <td>
                        <span class="badge ${threatBadge(log.threat_score)}">
                            ${log.threat_score}
                        </span>
                    </td>
                `;


                tbody.appendChild(tr);
            });
        })
        .catch(err => console.error("Load logs error:", err));
}

// ======================
// PAYLOAD MODAL
// ======================

function showPayload(payload) {
    const modalBody = document.getElementById("payloadModalBody");
    modalBody.textContent = payload || "(empty)";
    const modal = new bootstrap.Modal(document.getElementById("payloadModal"));
    modal.show();
}

function showResponse(resp) {
    document.getElementById("responseModalBody").textContent =
        resp || "(empty)";
    new bootstrap.Modal(
        document.getElementById("responseModal")
    ).show();
}

// ======================
// USER AGENT MODAL
// ======================

function showUserAgent(ua) {
    const modalBody = document.getElementById("uaModalBody");
    modalBody.textContent = ua || "(empty)";
    const modal = new bootstrap.Modal(document.getElementById("uaModal"));
    modal.show();
}

// ======================
// FILTER PARAMS
// ======================

function getFilterParams() {
    return {
        ip: document.getElementById("filterIp").value,
        method: document.getElementById("filterMethod").value,
        status: document.getElementById("filterStatus").value,
        start: document.getElementById("filterStart").value,
        end: document.getElementById("filterEnd").value
    };
}

// ======================
// CHARTS
// ======================

let chartRequests, chartMethods, chartStatus;

function loadCharts() {
    const params = new URLSearchParams(getFilterParams()).toString();

    // Requests per minute
    fetch("/api/stats/requests?" + params)
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

    // Methods
    fetch("/api/stats/methods?" + params)
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

    // Status codes
    fetch("/api/stats/status?" + params)
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

// ======================
// INIT
// ======================

loadLogs();
loadCharts();
setInterval(loadCharts, 5000);

// dimana saya bisa melihat response nya, apa saya buat lagi fitur yaa?? sebenarnnya dari dulu saya ingin membuat beberapa fitur saya inginn pnya side bar, tapi saya bingnung apa yang mau saay tambahkan sekranga saya bepikir untuk menambhakan full monitoring yang menampilkan request dan response, ip yang di blokir dll,  menurutmnu apa lagi yang perlu saya masukkan??  