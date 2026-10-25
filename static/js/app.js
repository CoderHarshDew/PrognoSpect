const attackStages=[
 {current:"Reconnaissance",next:"Resource Development",risk:8,confidence:58,k1:["Resource Development",58],k2:["Initial Access",46],k3:["Execution",34],active:"Host-01",predicted:"Host-01"},
 {current:"Resource Development",next:"Initial Access",risk:17,confidence:64,k1:["Initial Access",64],k2:["Execution",52],k3:["Persistence",39],active:"Host-01",predicted:"Host-03"},
 {current:"Initial Access",next:"Execution",risk:26,confidence:71,k1:["Execution",71],k2:["Persistence",58],k3:["Privilege Escalation",45],active:"Host-03",predicted:"Host-03"},
 {current:"Execution",next:"Persistence",risk:34,confidence:76,k1:["Persistence",76],k2:["Privilege Escalation",63],k3:["Defense Evasion",50],active:"Host-03",predicted:"Host-03"},
 {current:"Persistence",next:"Privilege Escalation",risk:42,confidence:79,k1:["Privilege Escalation",79],k2:["Defense Evasion",66],k3:["Credential Access",53],active:"Host-03",predicted:"Host-05"},
 {current:"Privilege Escalation",next:"Defense Evasion",risk:50,confidence:82,k1:["Defense Evasion",82],k2:["Credential Access",69],k3:["Discovery",56],active:"Host-05",predicted:"Host-05"},
 {current:"Defense Evasion",next:"Credential Access",risk:58,confidence:85,k1:["Credential Access",85],k2:["Discovery",73],k3:["Lateral Movement",60],active:"Host-05",predicted:"Host-07"},
 {current:"Credential Access",next:"Discovery",risk:65,confidence:87,k1:["Discovery",87],k2:["Lateral Movement",76],k3:["Collection",63],active:"Host-07",predicted:"Host-07"},
 {current:"Discovery",next:"Lateral Movement",risk:72,confidence:89,k1:["Lateral Movement",89],k2:["Collection",79],k3:["Command and Control",66],active:"Host-07",predicted:"Host-07"},
 {current:"Lateral Movement",next:"Collection",risk:79,confidence:91,k1:["Collection",91],k2:["Command and Control",82],k3:["Exfiltration",70],active:"Host-07",predicted:"Host-12"},
 {current:"Collection",next:"Command and Control",risk:85,confidence:92,k1:["Command and Control",92],k2:["Exfiltration",85],k3:["Impact",74],active:"Host-12",predicted:"Host-12"},
 {current:"Command and Control",next:"Exfiltration",risk:91,confidence:94,k1:["Exfiltration",94],k2:["Impact",88],k3:["Impact",78],active:"Host-12",predicted:"Data Server"},
 {current:"Exfiltration",next:"Impact",risk:97,confidence:96,k1:["Impact",96],k2:["Impact",90],k3:["Impact",80],active:"Data Server",predicted:"Database"}
];
let currentStage=1;
let deadlineSeconds=138;

document.addEventListener("DOMContentLoaded",()=>{
  setActiveNav();
  updateClock();
  setInterval(updateClock,1000);
  if(document.body.classList.contains("app-body")){
    updateSimulation();
    setInterval(updateSimulation,20000);
    setInterval(tickDeadline,1000);
  }
  if(document.getElementById("hostSearch")) filterHosts();
});

function setActiveNav(){
  const page=(location.pathname.split("/").pop()||"dashboard.html").replace(".html","");
  document.querySelectorAll(".nav-link[data-page]").forEach(a=>a.classList.toggle("active",a.dataset.page===page));
}
function updateClock(){
  const el=document.getElementById("liveClock"); if(!el)return;
  const d=new Date(); el.textContent=d.toLocaleTimeString([], {hour12:false});
}
function updateSimulation(){
  const data=attackStages[currentStage];
  setText("riskValue",data.risk+"%");
  setText("riskLabel",riskText(data.risk));
  setText("gaugeValue",data.risk);
  setText("riskLevel",riskLevel(data.risk));
  setText("confidence",data.confidence+"%");
  setText("currentStage",data.current);
  setText("nextStage",data.next);
  setText("insightStage",data.next);
  setText("insightConfidence",data.confidence+"%");
  const flow=12482+currentStage*337;
  setText("flowCount",flow.toLocaleString());
  setText("alertCount",String(7+currentStage).padStart(2,"0"));
  setText("hostCount",String(42+currentStage));
  const gauge=document.getElementById("riskGauge");
  if(gauge) gauge.style.background=`conic-gradient(var(--red) 0deg ${data.risk*3.6}deg,#173451 ${data.risk*3.6}deg 360deg)`;
  updateNetworkStages(data);
  updateDashboardPath(data);
  showToast(`Simulation updated · ${data.current} → ${data.next}`);
  currentStage=(currentStage+1)%attackStages.length;
}
function updateDashboard(){updateSimulation()}
function updateRiskLevel(){const d=attackStages[currentStage];setText("riskLevel",riskLevel(d.risk))}
function updateNetworkStages(data){
  const track=document.getElementById("stageTrack"); if(!track)return;
  const stages=["Reconnaissance","Resource Development","Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion","Credential Access","Discovery","Lateral Movement","Collection","Command and Control","Exfiltration","Impact"];
  const currentIndex=stages.indexOf(data.current);
  const nextIndex=stages.indexOf(data.next);
  const values=[null,null,data.k1?.[1],data.k2?.[1],data.k3?.[1]];
  track.innerHTML=stages.map((s,i)=>{
    let cls=i<currentIndex?"done":i===currentIndex?"done":i===nextIndex?"active":"future";
    const label=i<currentIndex?"Observed":i===currentIndex?"Current":i===nextIndex?`K+1 · ${data.confidence}%`:`K+${i-nextIndex+1} · ${values[i]||"—"}%`;
    return `<div class="stage ${cls}"><span>${i<=currentIndex?"✓":i}</span><b>${s}</b><small>${label}</small></div>${i<stages.length-1?"<i></i>":""}`;
  }).join("");
}
function updateDashboardPath(data){
  const hostNodes=document.querySelectorAll(".node-title");
  if(hostNodes.length>=2){hostNodes[1].textContent=data.active;hostNodes[2].textContent=data.predicted;}
}
function updatePredictionPage(){updateSimulation()}
function updateWorldModelInsight(){updateSimulation()}
function updateCostAwareActions(){/* modular hook for future policy UI */}
function updateAttackerTempo(){/* modular hook for future tempo UI */}
function tickDeadline(){
  const ids=["deadlineClock","deadlineLarge"];
  deadlineSeconds=deadlineSeconds>0?deadlineSeconds-1:138;
  const m=String(Math.floor(deadlineSeconds/60)).padStart(2,"0"),s=String(deadlineSeconds%60).padStart(2,"0");
  ids.forEach(id=>setText(id,`${m}:${s}`));
}
function riskLevel(v){return v>=90?"CRITICAL":v>=70?"HIGH":v>=50?"MEDIUM":"LOW"}
function riskText(v){return riskLevel(v)+" RISK"}
function setText(id,value){const el=document.getElementById(id);if(el)el.textContent=value}
function showToast(message){
  const el=document.getElementById("toast");if(!el)return;
  el.textContent=message;el.classList.add("show");clearTimeout(window.__toast);
  window.__toast=setTimeout(()=>el.classList.remove("show"),2200);
}
function toggleAttackPath(){
  document.querySelectorAll(".attack-path").forEach(e=>e.style.opacity=e.style.opacity==="0"?"1":"0");
  showToast("Predicted attack path toggled");
}
function resetMap(){
  document.querySelectorAll(".attack-path").forEach(e=>e.style.opacity="1");
  showToast("Attack map reset");
}
function filterHosts(){
  const input=document.getElementById("hostSearch");const table=document.getElementById("hostTable");if(!input||!table)return;
  const q=input.value.toLowerCase();
  table.querySelectorAll("tbody tr").forEach(row=>row.style.display=row.textContent.toLowerCase().includes(q)?"":"none");
}