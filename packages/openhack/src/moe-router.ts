import { GlobalConfig } from "./global-config"
import { ModelCosts } from "./model-costs"
import { loadJSON, saveJSON } from "./persist"

export namespace MOERouter {
  interface Expert { name: string; description: string; triggerWords: string[]; targetAgent: string; useCount: number }

  const EXPERTS: Expert[] = [
    { name:"port_scan", description:"Port scanning and service discovery", triggerWords:["nmap","rustscan","masscan","port","scan"], targetAgent:"recon", useCount:0 },
    { name:"dns_subdomain", description:"DNS enumeration", triggerWords:["dns","subdomain","amass","subfinder","dnsenum"], targetAgent:"recon", useCount:0 },
    { name:"web_exploit", description:"Web app vulnerability exploitation", triggerWords:["sqlmap","sqli","xss","csrf","ssrf","nuclei","injection"], targetAgent:"exploit", useCount:0 },
    { name:"network_exploit", description:"Network service exploitation", triggerWords:["metasploit","msfvenom","reverse shell","meterpreter","hydra","responder","impacket"], targetAgent:"exploit", useCount:0 },
    { name:"ad_windows", description:"Active Directory exploitation", triggerWords:["active directory","domain","bloodhound","kerberos","ntlm","ldap","smb","winrm"], targetAgent:"post-exploit", useCount:0 },
    { name:"binary_re", description:"Binary reverse engineering", triggerWords:["binary","ghidra","radare","gdb","disassemble","debug","elf"], targetAgent:"exploit", useCount:0 },
    { name:"cloud_container", description:"Cloud security", triggerWords:["aws","azure","gcp","kubernetes","docker","container","cloud"], targetAgent:"exploit", useCount:0 },
    { name:"hash_cracking", description:"Password cracking", triggerWords:["hash","crack","password","john","hashcat","ntlm","brute"], targetAgent:"post-exploit", useCount:0 },
    { name:"osint", description:"OSINT gathering", triggerWords:["osint","theharvester","sherlock","shodan","whois"], targetAgent:"recon", useCount:0 },
    { name:"reporting", description:"Report generation", triggerWords:["report","finding","sysreptor","export","pdf","cwe","cvss"], targetAgent:"report", useCount:0 },
    // NB: routes to "general" (a defined agent) — there is no "defense" agent, and
    // this expert is also the no-match fallback, so its target MUST exist.
    { name:"defense_blueteam", description:"Blue team risk assessment / review", triggerWords:["false positive","risk","defense","blue team","verify"], targetAgent:"general", useCount:0 },
    { name:"c2_operations", description:"C2 operations", triggerWords:["c2","arcticfox","implant","beacon","agent deploy"], targetAgent:"c2", useCount:0 },
  ]

  // Usage counts persist so routing statistics accumulate across the one-shot CLI
  // and the long-running server instead of resetting to zero every process.
  const STATS_FILE = ".openhack/moe-stats.json"
  {
    const saved = loadJSON<Record<string, number>>(STATS_FILE, {})
    for (const e of EXPERTS) if (typeof saved[e.name] === "number") e.useCount = saved[e.name]
  }
  function persistStats(): void {
    saveJSON(STATS_FILE, Object.fromEntries(EXPERTS.map((e) => [e.name, e.useCount])))
  }

  /** Classify a prompt to its best-matching expert without recording usage (pure). */
  function bestExpert(prompt:string):{expert:Expert;confidence:number}{
    const l=prompt.toLowerCase()
    let best:Expert|null=null;let bestCount=0
    for(const e of EXPERTS){let count=0;for(const w of e.triggerWords){if(l.includes(w))count++};if(count>bestCount){bestCount=count;best=e}}
    if(best&&bestCount>0)return{expert:best,confidence:Math.min(1,bestCount/Math.max(3,best.triggerWords.length))}
    return{expert:EXPERTS.find(e=>e.name==="defense_blueteam")||EXPERTS[0],confidence:0.05}
  }

  /** Route a prompt to an expert AND record the routing (increments + persists usage). */
  export function route(prompt:string):{expert:Expert;confidence:number}{
    const result=bestExpert(prompt)
    result.expert.useCount++;persistStats()
    return result
  }

  const CHEAP_EXPERTS=new Set(["port_scan","dns_subdomain","osint"])
  export function getModelForTask(prompt:string):string{
    const {expert}=bestExpert(prompt)
    return CHEAP_EXPERTS.has(expert.name)?GlobalConfig.fast():GlobalConfig.main()
  }
  export function getAgentForTask(prompt:string):string{return route(prompt).expert.targetAgent}
  export function getStats(){const model=GlobalConfig.main();return{experts:EXPERTS.map(e=>({name:e.name,useCount:e.useCount,agent:e.targetAgent,model})),total:EXPERTS.reduce((s,e)=>s+e.useCount,0)}}
  export function getCostEstimate(prompt:string):{model:string;estimatedCost:string;cheapest:boolean}{
    const m=GlobalConfig.main()
    // Shared rate table (model-costs.ts) — assume a small ~500-token reply for
    // the hint, matching the previous behaviour.
    const cost=ModelCosts.estimateUsd(m,prompt.length,500).toFixed(4)
    return{model:m,estimatedCost:`$${cost}`,cheapest:ModelCosts.isCheap(m)}
  }
}
