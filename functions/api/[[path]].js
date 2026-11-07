// BNT Pelota Dominicana - licencias con confirmacion manual (Cloudflare Pages + D1).
// No habilitar cobro ni restringir los juegos antes de verificar autorizaciones comerciales.
const jsonHeaders={"content-type":"application/json; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff"};
const today=()=>new Date().toISOString().slice(0,10);
let initPromise=null;
const json=(value,status=200,headers={})=>new Response(JSON.stringify(value),{status,headers:{...jsonHeaders,...headers}});
const reject=(message,status=400)=>json({ok:false,error:message},status);
function cleanPhone(value){
 let v=String(value||"").replace(/\D/g,"");
 if(v.length===11&&v.startsWith("1"))v=v.slice(1);
 return v.length===10&&/^(809|829|849)/.test(v)?v:null;
}
function safeText(value,max=80){return typeof value==="string"?value.trim().slice(0,max+1):"";}
function hex(bytes){return Array.from(bytes).map(x=>x.toString(16).padStart(2,"0")).join("");}
async function sha(value){return hex(new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value))));}
async function hashedPin(pin,salt){
 const k=await crypto.subtle.importKey("raw",new TextEncoder().encode(pin),"PBKDF2",false,["deriveBits"]);
 return hex(new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",iterations:100000,salt:new TextEncoder().encode(salt)},k,256)));
}
function secureEqual(a,b){if(a.length!==b.length)return false;let diff=0;for(let i=0;i<a.length;i++)diff|=a.charCodeAt(i)^b.charCodeAt(i);return diff===0;}
function addMonths(date,months){
 const d=new Date(date+"T12:00:00Z"),day=d.getUTCDate();
 d.setUTCDate(1);d.setUTCMonth(d.getUTCMonth()+months);
 const last=new Date(Date.UTC(d.getUTCFullYear(),d.getUTCMonth()+1,0)).getUTCDate();
 d.setUTCDate(Math.min(day,last));
 return d.toISOString().slice(0,10);
}
async function initialize(db){
 if(!initPromise){
  initPromise=(async()=>{
   await db.prepare("CREATE TABLE IF NOT EXISTS bnt_members (id TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL UNIQUE, pin_salt TEXT NOT NULL, pin_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', paid_until TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)").run();
   await db.prepare("CREATE TABLE IF NOT EXISTS bnt_payments (id TEXT PRIMARY KEY, member_id TEXT NOT NULL, amount_cents INTEGER NOT NULL, currency TEXT NOT NULL, months INTEGER NOT NULL, previous_until TEXT, new_until TEXT NOT NULL, reference TEXT, created_at TEXT NOT NULL, FOREIGN KEY(member_id) REFERENCES bnt_members(id))").run();
   await db.prepare("CREATE INDEX IF NOT EXISTS bnt_payments_member_idx ON bnt_payments(member_id,created_at)").run();
   await db.prepare("CREATE TABLE IF NOT EXISTS bnt_sessions (token_hash TEXT PRIMARY KEY, actor TEXT NOT NULL, member_id TEXT, expires_at INTEGER NOT NULL)").run();
   await db.prepare("CREATE TABLE IF NOT EXISTS bnt_limits (key TEXT PRIMARY KEY, period_start INTEGER NOT NULL, count INTEGER NOT NULL)").run();
   await db.prepare("CREATE TABLE IF NOT EXISTS bnt_entitlements (member_id TEXT PRIMARY KEY, trial_until TEXT NOT NULL, plan TEXT NOT NULL DEFAULT 'trial', updated_at TEXT NOT NULL)").run();
   await db.prepare("CREATE TABLE IF NOT EXISTS bnt_payment_types (payment_id TEXT PRIMARY KEY, plan TEXT NOT NULL)").run();
   await db.prepare("CREATE TABLE IF NOT EXISTS bnt_visits (visitor_hash TEXT NOT NULL, day TEXT NOT NULL, member_id TEXT, hits INTEGER NOT NULL DEFAULT 1, last_seen TEXT NOT NULL, PRIMARY KEY(visitor_hash,day))").run();
   await db.prepare("CREATE INDEX IF NOT EXISTS bnt_visits_member_idx ON bnt_visits(member_id,day)").run();
   // Para las cuentas existentes, el período de prueba parte de la fecha original del registro.
   const previous=await db.prepare("SELECT id,created_at FROM bnt_members WHERE id NOT IN (SELECT member_id FROM bnt_entitlements)").all();
   for(const m of previous.results||[]){
    await db.prepare("INSERT OR IGNORE INTO bnt_entitlements(member_id,trial_until,updated_at) VALUES(?,?,?)").bind(m.id,new Date(Date.parse(m.created_at)+259200000).toISOString(),new Date().toISOString()).run();
   }
  })().catch(e=>{initPromise=null;throw e;});
 }
 return initPromise;
}
async function readBody(request){
 const length=Number(request.headers.get("content-length")||"0");
 if(length>2500)throw Error("Contenido demasiado grande");
 const text=await request.text();
 if(text.length>2500)throw Error("Contenido demasiado grande");
 const data=JSON.parse(text);
 if(!data||typeof data!=="object"||Array.isArray(data))throw Error("Solicitud no valida");
 return data;
}
function sameOrigin(req){
 const origin=req.headers.get("origin");
 if(origin&&origin!==new URL(req.url).origin)return false;
 const site=req.headers.get("sec-fetch-site");
 return site!=="cross-site";
}
function tokenCookie(request){
 const header=request.headers.get("cookie")||"";
 const match=header.match(/(?:^|;\s*)bnt_session=([A-Za-z0-9_-]{35,})/);
 return match?match[1]:null;
}
function sessionCookie(token,age){return "bnt_session="+token+"; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age="+age;}
async function createSession(db,actor,memberId){
 const token=crypto.randomUUID().replace(/-/g,"")+crypto.randomUUID().replace(/-/g,"");
 const age=actor==="admin"?8*3600:30*86400;
 await db.prepare("INSERT INTO bnt_sessions (token_hash,actor,member_id,expires_at) VALUES (?,?,?,?)").bind(await sha(token),actor,memberId||null,Math.floor(Date.now()/1000)+age).run();
 return sessionCookie(token,age);
}
async function session(db,request){
 const token=tokenCookie(request);
 if(!token)return null;
 const record=await db.prepare("SELECT actor,member_id,expires_at FROM bnt_sessions WHERE token_hash=?").bind(await sha(token)).first();
 if(!record||Number(record.expires_at)<=Math.floor(Date.now()/1000))return null;
 return record;
}
async function limit(db,key,max,seconds){
 const now=Math.floor(Date.now()/1000);
 const rec=await db.prepare("SELECT count,period_start FROM bnt_limits WHERE key=?").bind(key).first();
 if(!rec||now-Number(rec.period_start)>=seconds){
  await db.prepare("INSERT INTO bnt_limits(key,period_start,count) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET period_start=excluded.period_start,count=1").bind(key,now).run();
  return true;
 }
 if(Number(rec.count)>=max)return false;
 await db.prepare("UPDATE bnt_limits SET count=count+1 WHERE key=?").bind(key).run();
 return true;
}
async function memberRecord(db,id){
 return db.prepare("SELECT m.id,m.name,m.phone,m.status,m.paid_until,m.created_at,e.trial_until,e.plan FROM bnt_members m LEFT JOIN bnt_entitlements e ON e.member_id=m.id WHERE m.id=?").bind(id).first();
}
function memberView(m){
 if(!m)return null;
 const paid=m.status==="active"&&!!m.paid_until&&m.paid_until>=today();
 const trial=!paid&&m.status!=="suspended"&&m.trial_until&&Date.parse(m.trial_until)>Date.now();
 const status=m.status==="suspended"?"suspended":paid?"active":trial?"trial":m.paid_until||m.trial_until?"expired":"pending";
 return {id:m.id,name:m.name,phone:m.phone,status,paid_until:m.paid_until,trial_until:m.trial_until,
  plan:paid?(m.plan==="season"?"season":"monthly"):trial?"trial":m.plan,access_until:paid?m.paid_until:trial?m.trial_until:null,
  active:!!(paid||trial),created_at:m.created_at};
}
const SEASON_END="2027-03-31"; // Vencimiento técnico de la temporada 2026-27, ajustable a la final real.
async function sportsJSON(path){
 const ctrl=new AbortController();const timeout=setTimeout(()=>ctrl.abort(),11000);
 try{
  const response=await fetch("https://statsapi.mlb.com"+path,{signal:ctrl.signal});
  if(!response.ok)throw Error("Datos deportivos no disponibles");
  return json(await response.json());
 }finally{clearTimeout(timeout)}
}
export async function onRequest(context){
 const {request,env}=context;
 const pathname=new URL(request.url).pathname.replace(/\/+$/,"");
 const route=pathname.replace(/^\/api\/?/,"");
 if(request.method!=="GET"&&request.method!=="POST")return reject("Metodo no permitido",405);
 if(request.method==="POST"&&!sameOrigin(request))return reject("Origen no permitido",403);
 // Comprobación segura del registro, sin información de clientes ni contraseñas.
 if(route==="health"&&request.method==="GET"){
  const configured=!!env.DB&&typeof env.BNT_ADMIN_PASSWORD==="string"&&env.BNT_ADMIN_PASSWORD.length>=12;
  if(!configured)return json({ok:false,stage:"configuration",code:"MISSING_CONFIGURATION"},503);
  let stage="database_schema";
  try{
   await initialize(env.DB);
   stage="database_read";
   await env.DB.prepare("SELECT COUNT(*) AS total FROM bnt_members").first();
   stage="rate_limit";
   await limit(env.DB,"selfcheck:"+today(),10000,3600);
   stage="pin_hash";
   const digest=await hashedPin("000000","healthcheck");
   if(digest.length!==64)throw Error("Invalid hash length");
   return json({ok:true,db:"ready",rate_limit:"ready",pin_hash:"ready"});
  }catch(error){
   console.error("BNT health:",stage,error instanceof Error?error.message:"Error");
   return json({ok:false,stage,code:"SERVICE_CHECK_FAILED"},503);
  }
 }
 if(route==="status"&&request.method==="GET")return json({ok:true,configured:!!env.DB&&typeof env.BNT_ADMIN_PASSWORD==="string"&&env.BNT_ADMIN_PASSWORD.length>=12,plans:{trial_days:3,monthly_usd:3,season_usd:8},mode:"transferencia_manual"});
 if(!env.DB||typeof env.BNT_ADMIN_PASSWORD!=="string"||env.BNT_ADMIN_PASSWORD.length<12)return reject("Suscripciones aun en configuracion",503);
 try{
  await initialize(env.DB);
  const db=env.DB;
  if(route==="register"&&request.method==="POST"){
   const data=await readBody(request),name=safeText(data.name),phone=cleanPhone(data.phone),pin=String(data.pin||"");
   if(name.length<3||name.length>80||!phone||!/^\d{6,8}$/.test(pin))return reject("Nombre, telefono dominicano y PIN de 6 a 8 digitos requeridos");
   const originKey=await sha(request.headers.get("cf-connecting-ip")||"sin-ip");
   if(!await limit(db,"signup:"+originKey,8,3600))return reject("Demasiados intentos. Prueba mas tarde",429);
   const salt=crypto.randomUUID();
   try{
    await db.prepare("INSERT INTO bnt_members(id,name,phone,pin_salt,pin_hash,status,paid_until,created_at,updated_at) VALUES(?,?,?,?,?,'pending',NULL,?,?)")
      .bind(crypto.randomUUID(),name,phone,salt,await hashedPin(pin,salt),new Date().toISOString(),new Date().toISOString()).run();
   }catch(e){
    if(/UNIQUE/i.test(String(e)))return reject("Este telefono ya esta registrado",409);
    throw e;
   }
   const registered=await db.prepare("SELECT id,created_at FROM bnt_members WHERE phone=?").bind(phone).first();
   await db.prepare("INSERT OR IGNORE INTO bnt_entitlements(member_id,trial_until,updated_at) VALUES(?,?,?)").bind(registered.id,new Date(Date.parse(registered.created_at)+259200000).toISOString(),new Date().toISOString()).run();
   return json({ok:true,message:"Registro recibido. Entra con tu telefono y PIN para disfrutar 3 dias gratis."},201);
  }
  if(route==="login"&&request.method==="POST"){
   const data=await readBody(request),phone=cleanPhone(data.phone),pin=String(data.pin||"");
   if(!phone||!/^\d{6,8}$/.test(pin))return reject("Credenciales invalidas",401);
   const key="login:"+(await sha(phone));
   if(!await limit(db,key,8,900))return reject("Demasiados intentos. Intenta mas tarde",429);
   const row=await db.prepare("SELECT id,pin_salt,pin_hash FROM bnt_members WHERE phone=?").bind(phone).first();
   if(!row||!secureEqual(await hashedPin(pin,row.pin_salt),row.pin_hash))return reject("Telefono o PIN incorrecto",401);
   return json({ok:true,member:memberView(await memberRecord(db,row.id))},200,{"set-cookie":await createSession(db,"member",row.id)});
  }
  if(route==="admin/login"&&request.method==="POST"){
   const iphash=await sha(request.headers.get("cf-connecting-ip")||"sin-ip");
   if(!await limit(db,"admin:"+iphash,7,900))return reject("Demasiados intentos. Intenta mas tarde",429);
   const data=await readBody(request),password=String(data.password||"");
   if(password.length>300||!secureEqual(await sha(password),await sha(env.BNT_ADMIN_PASSWORD)))return reject("Clave incorrecta",401);
   return json({ok:true,role:"admin"},200,{"set-cookie":await createSession(db,"admin",null)});
  }
  if(route==="logout"&&request.method==="POST"){
   const token=tokenCookie(request);
   if(token)await db.prepare("DELETE FROM bnt_sessions WHERE token_hash=?").bind(await sha(token)).run();
   return json({ok:true},200,{"set-cookie":sessionCookie("",0)});
  }
  // Visitas únicas aproximadas por navegador y día; no se guarda IP en el historial.
  if(route==="visit"&&request.method==="POST"){
   const data=await readBody(request),visitor=String(data.visitor||"");
   if(!new RegExp("^[a-f0-9]{32}$").test(visitor))return reject("Identificador de visita invalido");
   const current=await session(db,request),memberId=current?.actor==="member"?current.member_id:null,now=new Date().toISOString();
   await db.prepare("INSERT INTO bnt_visits(visitor_hash,day,member_id,hits,last_seen) VALUES(?,?,?,1,?) ON CONFLICT(visitor_hash,day) DO UPDATE SET member_id=COALESCE(excluded.member_id,bnt_visits.member_id),hits=hits+1,last_seen=excluded.last_seen")
     .bind(await sha(visitor),today(),memberId,now).run();
   return json({ok:true});
  }
  const auth=await session(db,request);
  if(route==="access"&&request.method==="GET"){
    if(!auth)return json({ok:true,role:"anonymous",allowed:false});
    if(auth.actor==="admin")return json({ok:true,role:"admin",allowed:true});
    const member=memberView(await memberRecord(db,auth.member_id));
    return json({ok:true,role:"member",allowed:!!member?.active,member});
  }
  if(!auth)return reject("Debes iniciar sesion",401);
  if(request.method==="GET"&&(route==="games"||route.startsWith("game/"))){
   const allowed=auth.actor==="admin"||memberView(await memberRecord(db,auth.member_id))?.active;
   if(!allowed)return reject("La prueba o mensualidad ha vencido. Calendario y Posiciones continúan gratis.",403);
   if(route==="games"){
    const query=new URL(request.url).searchParams,from=query.get("from"),to=query.get("to"),datePattern=new RegExp("^\\d{4}-\\d{2}-\\d{2}$");
    if(!datePattern.test(from||"")||!datePattern.test(to||""))return reject("Fecha invalida");
    const difference=(Date.parse(to+"T12:00:00Z")-Date.parse(from+"T12:00:00Z"))/86400000;
    if(!Number.isInteger(difference)||difference<0||difference>2)return reject("Rango no permitido");
    return sportsJSON("/api/v1/schedule?sportId=17&leagueId=131&startDate="+from+"&endDate="+to+"&hydrate=linescore,probablePitcher");
   }
   const pk=route.slice(5);
   if(!new RegExp("^\\d{5,12}$").test(pk))return reject("Juego invalido");
   return sportsJSON("/api/v1.1/game/"+pk+"/feed/live");
  }
  if(route==="me"&&request.method==="GET"){
   if(auth.actor==="admin")return json({ok:true,role:"admin"});
   const m=await memberRecord(db,auth.member_id);
   if(!m)return reject("Cuenta no encontrada",404);
   return json({ok:true,role:"member",member:memberView(m)});
  }
  if(auth.actor!=="admin")return reject("Acceso exclusivo del administrador",403);
  if(route==="admin/members"&&request.method==="GET"){
   const data=await db.prepare("SELECT m.id,m.name,m.phone,m.status,m.paid_until,m.created_at,e.trial_until,e.plan,(SELECT MAX(v.last_seen) FROM bnt_visits v WHERE v.member_id=m.id) AS last_visit FROM bnt_members m LEFT JOIN bnt_entitlements e ON e.member_id=m.id ORDER BY m.created_at DESC LIMIT 500").all();
   const list=(data.results||[]).map(m=>({...memberView(m),last_visit:m.last_visit}));
   return json({ok:true,members:list,summary:{total:list.length,active:list.filter(m=>m.status==="active").length,trial:list.filter(m=>m.status==="trial").length,pending:list.filter(m=>m.status==="pending").length,expired:list.filter(m=>m.status==="expired").length,suspended:list.filter(m=>m.status==="suspended").length}});
  }
  if(route==="admin/analytics"&&request.method==="GET"){
   const day=today();
   const v=await db.prepare("SELECT COUNT(*) AS visitors,COUNT(DISTINCT member_id) AS logged_members,COALESCE(SUM(hits),0) AS total_visits FROM bnt_visits WHERE day=?").bind(day).first();
   const p=await db.prepare("SELECT COALESCE(SUM(amount_cents),0) AS revenue_cents FROM bnt_payments").first();
   return json({ok:true,day,unique_visitors:v.visitors||0,logged_members:v.logged_members||0,total_visits:v.total_visits||0,revenue_usd:Number(p.revenue_cents||0)/100});
  }
  if(route==="admin/pay"&&request.method==="POST"){
   const data=await readBody(request),id=safeText(data.member_id,64),plan=data.plan,reference=safeText(data.reference||"",100);
   if(!new RegExp("^[a-zA-Z0-9-]{36}$").test(id)||!["monthly","season"].includes(plan))return reject("Cliente o plan invalido");
   const m=await memberRecord(db,id);
   if(!m)return reject("Cliente no encontrado",404);
   const start=plan==="monthly"&&m.status==="active"&&m.paid_until&&m.paid_until>=today()?m.paid_until:today();
   const until=plan==="monthly"?addMonths(start,1):SEASON_END,price=plan==="monthly"?300:800;
   if(until<today())return reject("La temporada ha terminado; no aceptes este plan",409);
   const stamp=new Date().toISOString(),paymentId=crypto.randomUUID();
   await db.batch([
    db.prepare("INSERT INTO bnt_payments(id,member_id,amount_cents,currency,months,previous_until,new_until,reference,created_at) VALUES(?,?,?,'USD',?,?,?,?,?)")
      .bind(paymentId,id,price,plan==="monthly"?1:0,m.paid_until||null,until,reference||null,stamp),
    db.prepare("INSERT INTO bnt_payment_types(payment_id,plan) VALUES(?,?)").bind(paymentId,plan),
    db.prepare("UPDATE bnt_members SET status='active',paid_until=?,updated_at=? WHERE id=?").bind(until,stamp,id),
    db.prepare("UPDATE bnt_entitlements SET plan=?,updated_at=? WHERE member_id=?").bind(plan,stamp,id)
   ]);
   return json({ok:true,member:memberView(await memberRecord(db,id))});
  }
  if(route==="admin/status"&&request.method==="POST"){
   const data=await readBody(request),id=safeText(data.member_id,64),status=data.status;
   if(!/^[a-zA-Z0-9-]{36}$/.test(id)||!["suspended","active"].includes(status))return reject("Solicitud incorrecta");
   const m=await memberRecord(db,id);
   if(!m)return reject("Cliente no encontrado",404);
   await db.prepare("UPDATE bnt_members SET status=?,updated_at=? WHERE id=?").bind(status,new Date().toISOString(),id).run();
   return json({ok:true,member:memberView(await memberRecord(db,id))});
  }
  if(route==="admin/payments"&&request.method==="GET"){
   const data=await db.prepare("SELECT p.id,p.member_id,m.name,p.amount_cents,p.currency,p.months,p.previous_until,p.new_until,p.reference,p.created_at,COALESCE(t.plan,\'previous\') AS plan FROM bnt_payments p LEFT JOIN bnt_members m ON m.id=p.member_id LEFT JOIN bnt_payment_types t ON t.payment_id=p.id ORDER BY p.created_at DESC LIMIT 200").all();
   return json({ok:true,payments:data.results||[]});
  }
  return reject("Ruta no encontrada",404);
 }catch(error){
  console.error("BNT subscription error",error instanceof Error?error.message:"error");
  return reject("No se pudo completar la operacion. Intenta nuevamente",500);
 }
}
