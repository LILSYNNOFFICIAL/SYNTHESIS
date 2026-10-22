use chrono::{DateTime,Utc};
use serde::{Deserialize,Serialize};
use std::{process::Command,time::Duration};
use tokio::time::timeout;
use uuid::Uuid;
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ToolInfo{pub id:String,pub name:String,pub category:String,pub description:String,pub executable:String,pub installed:bool,pub risk:String}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Job{pub id:String,pub tool:String,pub target:String,pub status:String,pub started_at:DateTime<Utc>,pub output:String,pub success:bool}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct MissionPlan{pub title:String,pub summary:String,pub steps:Vec<String>,pub provider:String}
#[derive(Debug,Deserialize)]
struct OllamaResponse{message:Option<OllamaMessage>}
#[derive(Debug,Deserialize)]
struct OllamaMessage{content:String}
fn registry()->Vec<ToolInfo>{
 let specs=[("nmap","Nmap","Network","Discover hosts and inspect common TCP services.","nmap","Moderate"),("ping","Ping","Network","Check basic reachability for a host.","ping","Low"),("dig","DNS lookup","Web & DNS","Query DNS records for a domain.","dig","Low"),("whois","WHOIS","Web & DNS","Look up public domain registration data.","whois","Low")];
 specs.iter().map(|(id,name,category,description,executable,risk)|ToolInfo{id:(*id).into(),name:(*name).into(),category:(*category).into(),description:(*description).into(),executable:(*executable).into(),installed:command_exists(executable),risk:(*risk).into()}).collect()
}
fn command_exists(program:&str)->bool{std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).any(|p|p.join(program).is_file())}
fn validate_target(target:&str)->Result<(),String>{let v=target.trim();if v.is_empty()||v.len()>253{return Err("Target must contain between 1 and 253 characters.".into())}if v.starts_with('-'){return Err("Targets cannot begin with a dash.".into())}if !v.chars().all(|c|c.is_ascii_alphanumeric()||matches!(c,'.'|':'|'/'|'-')){return Err("Unsupported target characters. Use a hostname, IP address, or CIDR.".into())}if v.contains("..")||v.contains("//"){return Err("Target contains an invalid sequence.".into())}Ok(())}
#[tauri::command]fn list_tools()->Vec<ToolInfo>{registry()}
#[tauri::command]async fn check_ollama()->serde_json::Value{let client=reqwest::Client::builder().timeout(Duration::from_secs(2)).build();let available=match client{Ok(c)=>c.get("http://127.0.0.1:11434/api/tags").send().await.map(|r|r.status().is_success()).unwrap_or(false),Err(_)=>false};serde_json::json!({"available":available})}
#[tauri::command]async fn plan_mission(mission:String)->Result<MissionPlan,String>{
 let prompt=mission.trim();if prompt.is_empty()||prompt.len()>4000{return Err("Mission must contain between 1 and 4000 characters.".into())}
 let system="You are SYNTHESIS, a cautious security workflow planner. Return concise plain text, not JSON. Do not execute anything. Avoid exploit instructions, credential theft, stealth, persistence, and destructive actions. Give 3-5 reviewable steps for authorized defensive work. Remind the user to verify scope. Never invent results. Supported tools: Nmap for authorized service discovery, ping, dig, WHOIS.";
 let body=serde_json::json!({"model":std::env::var("SYNTHESIS_OLLAMA_MODEL").unwrap_or_else(|_|"qwen2.5:3b".into()),"stream":false,"messages":[{"role":"system","content":system},{"role":"user","content":prompt}]});
 let client=reqwest::Client::builder().timeout(Duration::from_secs(18)).build().map_err(|e|format!("Could not initialize local AI client: {e}"))?;
 if let Ok(Ok(response))=timeout(Duration::from_secs(19),client.post("http://127.0.0.1:11434/api/chat").json(&body).send()).await{if response.status().is_success(){if let Ok(payload)=response.json::<OllamaResponse>().await{if let Some(message)=payload.message{let steps:Vec<String>=message.content.lines().map(|s|s.trim().trim_start_matches(|c:char|c.is_ascii_digit()||c=='.'||c=='-'||c=='*').trim().to_string()).filter(|s|!s.is_empty()).take(6).collect();if !steps.is_empty(){return Ok(MissionPlan{title:"Mission plan".into(),summary:"AI-generated draft. Review scope and each step before action.".into(),steps,provider:"Ollama (local)".into()})}}}}}
 Ok(MissionPlan{title:"Mission plan".into(),summary:"Local AI is unavailable. This deterministic plan is a starter, and nothing has been executed.".into(),steps:vec!["Confirm you own the target or have explicit authorization.".into(),"Define the exact target and narrowest scope that answers the question.".into(),"Choose an installed supported tool and review its parameters.".into(),"Run only after checking the target and authorization acknowledgement.".into(),"Validate findings manually and document limitations.".into()],provider:"Offline fallback".into()})
}
#[tauri::command]async fn run_tool(tool_id:String,target:String,authorized:bool)->Result<Job,String>{
 if !authorized{return Err("Execution blocked: confirm that you own the target or have explicit authorization.".into())}validate_target(&target)?;
 let (program,args):(&str,Vec<String>)=match tool_id.as_str(){"nmap"=>("nmap",vec!["-sV".into(),"--top-ports".into(),"100".into(),target.clone()]),"ping"=>("ping",vec!["-c".into(),"4".into(),target.clone()]),"dig"=>("dig",vec![target.clone()]),"whois"=>("whois",vec![target.clone()]),_=>return Err("Unknown tool. Only registered adapters can execute.".into())};
 if !command_exists(program){return Err(format!("Required program '{program}' is not installed or not available in PATH."))}
 let started_at=Utc::now();let command=program.to_string();let worker_args=args.clone();
 let result=timeout(Duration::from_secs(45),tokio::task::spawn_blocking(move||Command::new(&command).args(&worker_args).output())).await;
 let (output,success)=match result{Err(_)=>("Execution timed out after 45 seconds. This preview does not guarantee termination of a hung child process.".to_string(),false),Ok(Err(e))=>(format!("Could not start worker: {e}"),false),Ok(Ok(Err(e)))=>(format!("Could not execute tool: {e}"),false),Ok(Ok(Ok(o)))=>{let stdout=String::from_utf8_lossy(&o.stdout);let stderr=String::from_utf8_lossy(&o.stderr);let mut text=format!("$ {} {}",program,args.join(" "));if !stdout.trim().is_empty(){text.push_str("\n\n");text.push_str(&stdout)}if !stderr.trim().is_empty(){text.push_str("\n\nSTDERR:\n");text.push_str(&stderr)}text.truncate(100_000);(text,o.status.success())}};
 Ok(Job{id:Uuid::new_v4().to_string(),tool:tool_id,target,status:if success{"Complete".into()}else{"Error".into()},started_at,output,success})
}
pub fn run(){tauri::Builder::default().invoke_handler(tauri::generate_handler![list_tools,check_ollama,plan_mission,run_tool]).run(tauri::generate_context!()).expect("error while running SYNTHESIS");}
#[cfg(test)]mod tests{use super::*;#[test]fn rejects_empty_target(){assert!(validate_target("").is_err());}#[test]fn rejects_option_injection(){assert!(validate_target("--script=evil").is_err());}#[test]fn rejects_shell_metacharacters(){assert!(validate_target("127.0.0.1;whoami").is_err());assert!(validate_target("example.com && id").is_err());}#[test]fn accepts_common_targets(){assert!(validate_target("127.0.0.1").is_ok());assert!(validate_target("192.168.1.0/24").is_ok());assert!(validate_target("example.org").is_ok());assert!(validate_target("2001:db8::1").is_ok());}#[test]fn only_known_adapters_are_registered(){let ids:Vec<String>=registry().into_iter().map(|t|t.id).collect();assert_eq!(ids,vec!["nmap","ping","dig","whois"]);}}
