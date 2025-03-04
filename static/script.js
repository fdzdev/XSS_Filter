document.addEventListener("DOMContentLoaded", function () {
    fetch("/api/results")
        .then(response => response.json())
        .then(data => {
            window.scanResults = data;
            displayResults(data);
        })
        .catch(error => console.error("Error loading scan results:", error));
});

function displayResults(data) {
    const container = document.getElementById("resultsContainer");
    container.innerHTML = "";

    // Sort results by severity!
    data.sort((a, b) => b["Final Score"] - a["Final Score"]);

    data.forEach((result) => {
        let resultCard = document.createElement("div");
        resultCard.className = "result-card";
        resultCard.innerHTML = `
            <h3>${result.URL}</h3>
            <p>⚠ Score: <b>${result["Final Score"]}</b> | Severity: <b>${result["Severity"]}</b></p>
        `;
        resultCard.onclick = () => showDetails(result);
        container.appendChild(resultCard);
    });
}

function filterResults() {
    let search = document.getElementById("searchBox").value.toLowerCase();
    let filteredData = window.scanResults.filter(result => result.URL.toLowerCase().includes(search));
    displayResults(filteredData);
}

function showDetails(result) {
    document.getElementById("detailTitle").innerText = result.URL;
    document.getElementById("detailInfo").innerHTML = `
        <p>🌎 <b>Asset Exposure:</b> ${result["Asset Exposure"]}</p>
        <p>🔒 <b>CSP Status:</b> ${result["CSP Status"]}</p>
        <p>🍪 <b>Cookie Access:</b> ${result["Cookie Access"]}</p>
        <p>📜 <b>XSS Execution:</b> ${result["XSS Execution"]}</p>
        <p>⚠ <b>Final Score:</b> ${result["Final Score"]}</p>
        <p>🔥 <b>Severity:</b> ${result["Severity"]}</p>
    `;
    document.getElementById("detailModal").style.display = "block";
}

function closeModal() {
    document.getElementById("detailModal").style.display = "none";
}