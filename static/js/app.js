// ==========================================
// PROGNOSPECT
// Predictive Cyber Defence Simulation
// ==========================================


// ==========================================
// LANDING PAGE
// ==========================================

function startAnalysis() {
    window.location.href = "dashboard.html";
}

function viewDemo() {
    window.location.href = "dashboard.html";
}


// ==========================================
// ATTACK SIMULATION STATES
// ==========================================

const attackStages = [

    {
        current: "Initial Access",
        next: "Discovery",

        risk: 45,
        confidence: 86,

        k1: "Discovery",
        k1Confidence: 86,

        k2: "Lateral Movement",
        k2Confidence: 72,

        k3: "Exfiltration",
        k3Confidence: 61,

        activeHost: "Host-07",
        predictedHost: "Host-12"
    },

    {
        current: "Discovery",
        next: "Lateral Movement",

        risk: 78,
        confidence: 91,

        k1: "Lateral Movement",
        k1Confidence: 91,

        k2: "Exfiltration",
        k2Confidence: 78,

        k3: "Critical Impact",
        k3Confidence: 64,

        activeHost: "Host-07",
        predictedHost: "Host-12"
    },

    {
        current: "Lateral Movement",
        next: "Exfiltration",

        risk: 89,
        confidence: 94,

        k1: "Exfiltration",
        k1Confidence: 94,

        k2: "Critical Impact",
        k2Confidence: 81,

        k3: "Service Disruption",
        k3Confidence: 68,

        activeHost: "Host-12",
        predictedHost: "Data Server"
    },

    {
        current: "Exfiltration",
        next: "Critical Impact",

        risk: 97,
        confidence: 96,

        k1: "Critical Impact",
        k1Confidence: 96,

        k2: "Service Disruption",
        k2Confidence: 88,

        k3: "Network Compromise",
        k3Confidence: 74,

        activeHost: "Data Server",
        predictedHost: "Database"
    }

];


// Current simulation position

let currentStage = 0;


// ==========================================
// MAIN SIMULATION UPDATE
// ==========================================

function updateSimulation() {

    const state = attackStages[currentStage];

    // Dashboard
    updateDashboard(state);

    // Dashboard state flow
    updateNetworkStages();

    // Attack Map
    updateAttackMap(state);

    // Future Prediction
    updatePredictionPage(state);

}


// ==========================================
// DASHBOARD UPDATE
// ==========================================

function updateDashboard(state) {

    const riskScore = document.getElementById("riskScore");
    const gaugeRisk = document.getElementById("gaugeRisk");

    const confidenceScore =
        document.getElementById("confidenceScore");

    const predictionStage =
        document.getElementById("predictionStage");

    const predictionConfidence =
        document.getElementById("predictionConfidence");

    const modelConfidence =
        document.getElementById("modelConfidence");

    const currentState =
        document.getElementById("currentState");

    const confidenceBar =
        document.getElementById("confidenceBar");


    if (riskScore)
        riskScore.textContent = state.risk;


    if (gaugeRisk)
        gaugeRisk.textContent = state.risk;


    if (confidenceScore)
        confidenceScore.textContent =
            state.confidence + "%";


    if (predictionStage)
        predictionStage.textContent =
            state.next;


    if (predictionConfidence)
        predictionConfidence.textContent =
            state.confidence + "%";


    if (modelConfidence)
        modelConfidence.textContent =
            state.confidence + "%";


    if (currentState)
        currentState.textContent =
            state.current;


    if (confidenceBar)
        confidenceBar.style.width =
            state.confidence + "%";


    updateRiskLevel(state.risk);
}


// ==========================================
// RISK LEVEL
// ==========================================

function updateRiskLevel(risk) {

    const riskLevel =
        document.getElementById("riskLevel");

    const riskTitle =
        document.getElementById("riskTitle");

    const riskDescription =
        document.getElementById("riskDescription");


    if (risk < 60) {

        if (riskLevel)
            riskLevel.textContent = "MEDIUM RISK";

        if (riskTitle)
            riskTitle.textContent = "MEDIUM RISK";

        if (riskDescription)
            riskDescription.textContent =
                "Network behaviour is being monitored for convergence toward compromise.";

    }

    else if (risk < 85) {

        if (riskLevel)
            riskLevel.textContent = "HIGH RISK";

        if (riskTitle)
            riskTitle.textContent = "HIGH RISK";

        if (riskDescription)
            riskDescription.textContent =
                "Network behaviour indicates increasing probability of attack progression.";

    }

    else {

        if (riskLevel)
            riskLevel.textContent = "CRITICAL RISK";

        if (riskTitle)
            riskTitle.textContent = "CRITICAL RISK";

        if (riskDescription)
            riskDescription.textContent =
                "Predicted trajectory strongly converges toward a potentially compromised state.";

    }

}


// ==========================================
// DASHBOARD NETWORK STAGES
// ==========================================

function updateNetworkStages() {

    const stages = [

        document.getElementById("stageInitial"),

        document.getElementById("stageDiscovery"),

        document.getElementById("stageLateral"),

        document.getElementById("stageExfiltration")

    ];


    if (!stages.some(stage => stage))
        return;


    stages.forEach(stage => {

        if (stage) {

            stage.classList.remove(
                "active",
                "predicted"
            );

        }

    });


    if (stages[currentStage]) {

        stages[currentStage]
            .classList.add("active");

    }


    if (stages[currentStage + 1]) {

        stages[currentStage + 1]
            .classList.add("predicted");

    }

}


// ==========================================
// ATTACK MAP UPDATE
// ==========================================

function updateAttackMap(state) {

    const nodes =
        document.querySelectorAll(".graph-node");


    if (!nodes.length)
        return;


    nodes.forEach(node => {

        node.classList.remove(
            "active",
            "predicted"
        );

    });


    nodes.forEach(node => {

        const hostName =
            node.dataset.host;


        if (hostName === state.activeHost) {

            node.classList.add("active");

        }


        if (
            hostName === state.predictedHost &&
            hostName !== state.activeHost
        ) {

            node.classList.add("predicted");

        }

    });

}


// ==========================================
// FUTURE PREDICTION PAGE
// ==========================================

function updatePredictionPage(state) {

    const currentState =
        document.getElementById(
            "predictionCurrentState"
        );

    const currentRisk =
        document.getElementById(
            "predictionCurrentRisk"
        );


    const k1 =
        document.getElementById("predictionK1");

    const k2 =
        document.getElementById("predictionK2");

    const k3 =
        document.getElementById("predictionK3");


    const confidenceK1 =
        document.getElementById("confidenceK1");

    const confidenceK2 =
        document.getElementById("confidenceK2");

    const confidenceK3 =
        document.getElementById("confidenceK3");


    const barK1 =
        document.getElementById("confidenceBarK1");

    const barK2 =
        document.getElementById("confidenceBarK2");

    const barK3 =
        document.getElementById("confidenceBarK3");


    // Current state

    if (currentState)
        currentState.textContent =
            state.current;


    if (currentRisk)
        currentRisk.textContent =
            state.risk;


    // K = 1

    if (k1)
        k1.textContent =
            state.k1;


    if (confidenceK1)
        confidenceK1.textContent =
            state.k1Confidence + "%";


    if (barK1)
        barK1.style.width =
            state.k1Confidence + "%";


    // K = 2

    if (k2)
        k2.textContent =
            state.k2;


    if (confidenceK2)
        confidenceK2.textContent =
            state.k2Confidence + "%";


    if (barK2)
        barK2.style.width =
            state.k2Confidence + "%";


    // K = 3

    if (k3)
        k3.textContent =
            state.k3;


    if (confidenceK3)
        confidenceK3.textContent =
            state.k3Confidence + "%";


    if (barK3)
        barK3.style.width =
            state.k3Confidence + "%";


    // Update model explanation

    updateWorldModelInsight(state);

}


// ==========================================
// WORLD MODEL INSIGHT
// ==========================================

function updateWorldModelInsight(state) {

    const title =
        document.getElementById(
            "worldModelTitle"
        );

    const insight =
        document.getElementById(
            "worldModelInsight"
        );


    if (!title && !insight)
        return;


    if (state.risk < 60) {

        if (title)
            title.textContent =
                "Early attack progression detected";

        if (insight)
            insight.textContent =
                "The current network state shows early suspicious activity. The model predicts Discovery as the most likely next stage.";

    }

    else if (state.risk < 85) {

        if (title)
            title.textContent =
                "Attack trajectory is converging";

        if (insight)
            insight.textContent =
                "The predicted trajectory indicates increasing internal movement and a higher probability of progression toward Exfiltration.";

    }

    else {

        if (title)
            title.textContent =
                "High-risk trajectory detected";

        if (insight)
            insight.textContent =
                "The current state strongly indicates continued attack progression. Future states show potential movement toward critical impact.";

    }

}


// ==========================================
// MOVE TO NEXT ATTACK STAGE
// ==========================================

function nextAttackStage() {

    currentStage++;

    if (currentStage >= attackStages.length) {

        currentStage = 0;

    }

    updateSimulation();

}


// ==========================================
// INITIALIZE
// ==========================================

document.addEventListener(
    "DOMContentLoaded",
    function () {

        updateSimulation();

        setInterval(
            nextAttackStage,
            5000
        );

    }
);