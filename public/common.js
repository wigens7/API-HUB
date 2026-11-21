const $ = (s, root=document) => root.querySelector(s);
const $$ = (s, root=document) => [...root.querySelectorAll(s)];
function toast(message){const el=$('#toast');el.textContent=message;el.classList.add('show');clearTimeout(window.__toastTimer);window.__toastTimer=setTimeout(()=>el.classList.remove('show'),3000)}
function esc(value){return String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function date(value){return value?new Date(value).toLocaleString():'—'}
function setRows(id,html,cols){$(id).innerHTML=html||`<tr><td colspan="${cols}" class="empty">No records found.</td></tr>`}
function tagClass(status){const s=String(status||'').toLowerCase();return s.includes('approv')||s==='active'?'active':s.includes('reject')||s==='suspended'||s==='cancelled'||s==='revoked'?'revoked':'pending'}
// Session lives in an httpOnly cookie set by the server; the page never sees the token.
async function api(url, options={}){const headers={'Content-Type':'application/json','X-Zytrelix-Client':'web',...(options.headers||{})};const res=await fetch(url,{...options,headers,credentials:'same-origin'});let data={};try{data=await res.json()}catch{}if(!res.ok){if(res.status===401||(res.status===403&&/suspended/i.test(data.error||''))){location.href='/login';}throw new Error(data.error||`Request failed (${res.status})`)}return data}
async function logout(){try{await api('/api/auth/logout',{method:'POST'})}catch{}location.href='/login'}
function initShell(pageNames, loaders, allowed){
 const pages=Object.keys(pageNames);
 function navigate(page){if(!pages.includes(page))return;$$('.page').forEach(el=>el.classList.toggle('active',el.id===`page-${page}`));$$('.nav-item').forEach(el=>el.classList.toggle('active',el.dataset.page===page));$('#crumb').textContent=pageNames[page];$('#sidebar').classList.remove('open');history.replaceState(null,'','#'+page);if(loaders[page])loaders[page]().catch(e=>toast(e.message))}
 $$('.nav-item').forEach(b=>b.addEventListener('click',()=>navigate(b.dataset.page)));
 $('#logoutBtn').addEventListener('click',logout);$('#mobileMenu').addEventListener('click',()=>$('#sidebar').classList.toggle('open'));
 const start=location.hash.slice(1);if(pages.includes(start)&&start!=='overview')navigate(start);
 return navigate;
}
