const attackStages=[
 {current:"Initial Access",next:"Discovery",risk:45,confidence:86,k1:["Discovery",86],k2:["Lateral Movement",72],k3:["Exfiltration",61],active:"Host-07",predicted:"Host-12"},
 {current:"Discovery",next:"Lateral Movement",risk:78,confidence:91,k1:["Lateral Movement",91],k2:["Exfiltration",78],k3:["Critical Impact",64],active:"Host-07",predicted:"Host-12"},
 {current:"Lateral Movement",next:"Exfiltration",risk:89,confidence:94,k1:["Exfiltration",94],k2:["Critical Impact",81],k3:["Service Disruption",68],active:"Host-12",predicted:"Data Server"},
 {current:"Exfiltration",next:"Critical Impact",risk:97,confidence:96,k1:["Critical Impact",96],k2:["Service Disruption",88],k3:["Network Compromise",74],active:"Data Server",predicted:"Database"}
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
  const stages=["Initial Access","Discovery","Lateral Movement","Exfiltration","Critical Impact"];
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
