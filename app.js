const pages = ['overview','api-keys','kyc','cards','transactions','documentation','webhooks'];
const names = {'overview':'Overview','api-keys':'API keys','kyc':'KYC submissions','cards':'Virtual cards','transactions':'Transactions','documentation':'Documentation','webhooks':'Webhooks'};
const $ = (s, root=document) => root.querySelector(s);
const $$ = (s, root=document) => [...root.querySelectorAll(s)];
function toast(message){const el=$('#toast');el.textContent=message;el.classList.add('show');clearTimeout(window.toastTimer);window.toastTimer=setTimeout(()=>el.classList.remove('show'),2600)}
function navigate(page){if(!pages.includes(page))return;$$('.page').forEach(p=>p.classList.remove('active-page'));$('#page-'+page).classList.add('active-page');$$('.nav-link').forEach(b=>b.classList.toggle('active',b.dataset.page===page));$('#crumb').textContent=names[page];$('#sidebar').classList.remove('open');window.location.hash=page;window.scrollTo({top:0,behavior:'smooth'})}
$$('.nav-link').forEach(b=>b.addEventListener('click',()=>navigate(b.dataset.page)));
$$('[data-go]').forEach(b=>b.addEventListener('click',()=>navigate(b.dataset.go)));
$('#mobileMenu').addEventListener('click',()=>$('#sidebar').classList.toggle('open'));
if(location.hash && pages.includes(location.hash.slice(1)))navigate(location.hash.slice(1));

const modal=$('#modal');
function openKeyModal(){modal.classList.add('open');$('#keyName').value='';$('#keyName').focus()}
function closeModal(){modal.classList.remove('open')}
$('#newKeyBtn').addEventListener('click',openKeyModal);
$('#modalClose').addEventListener('click',closeModal);$('#cancelModal').addEventListener('click',closeModal);
modal.addEventListener('click',e=>{if(e.target===modal)closeModal()});
$('#confirmModal').addEventListener('click',()=>{
  const name=$('#keyName').value.trim();if(!name){toast('Enter an application name first.');return;}
  const key='cv_test_'+Array.from(crypto.getRandomValues(new Uint8Array(12)),b=>b.toString(16).padStart(2,'0')).join('').slice(0,20);
  const tr=document.createElement('tr');
  const cells=[name,key.slice(0,10)+'••••••••'+key.slice(-4),'Sandbox',new Date().toLocaleDateString('en-US',{month:'short',day:'2-digit',year:'numeric'}),'Active'];
  tr.innerHTML=`<td><b>${escapeHtml(cells[0])}</b></td><td><code>${escapeHtml(cells[1])}</code></td><td><span class="tag tag-blue">Sandbox</span></td><td>${cells[3]}</td><td><span class="tag tag-green">Active</span></td><td><button class="dots" title="Copy demo key">···</button></td>`;
  $('#keysRows').prepend(tr);$('#keyCount').textContent=String(Number($('#keyCount').textContent)+1);closeModal();
  showSecret(`Demo key for ${name}`,key);
});
function escapeHtml(s){return s.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function showSecret(title,secret){const backdrop=document.createElement('div');backdrop.className='modal-backdrop open';backdrop.innerHTML=`<div class="modal"><button class="modal-close">×</button><div class="modal-icon">⚿</div><h2>${escapeHtml(title)}</h2><p>This is a locally generated demo credential. It is not connected to a live API and is not saved to a database.</p><pre style="white-space:pre-wrap;word-break:break-all;background:#152238;color:#d4e2f7;padding:12px;border-radius:7px;font-size:10px">${escapeHtml(secret)}</pre><div class="modal-actions"><button class="btn btn-primary">Copy key</button></div></div>`;document.body.append(backdrop);backdrop.querySelector('.modal-close').onclick=()=>backdrop.remove();backdrop.addEventListener('click',e=>{if(e.target===backdrop)backdrop.remove()});backdrop.querySelector('.btn').onclick=async()=>{await navigator.clipboard.writeText(secret);toast('Demo key copied.');backdrop.remove()}}

$('#kycFilter').addEventListener('change',e=>{$$('#kycRows tr').forEach(row=>row.style.display=e.target.value==='all'||row.dataset.status===e.target.value?'':'none')});
function exportTable(tableId,filename){const table=$(tableId);const rows=$$('tr',table).map(row=>$$('th,td',row).map(c=>'"'+c.innerText.replace(/\s+/g,' ').replace(/"/g,'""')+'"').join(','));const blob=new Blob([rows.join('\n')],{type:'text/csv'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=filename;a.click();URL.revokeObjectURL(url);toast('CSV export created.')}
$('#exportKyc').addEventListener('click',()=>exportTable('#kycRows','zytrelix-kyc-demo.csv'));
$('#exportActivity').addEventListener('click',()=>exportTable('#activityRows','zytrelix-activity-demo.csv'));
$('#createCardBtn').addEventListener('click',()=>toast('Card creation is a demo action. Configure provider credentials and KYC approval first.'));
$('#addWebhook').addEventListener('click',()=>toast('Webhook setup UI is a placeholder. Confirm signature verification with ZiiroPay first.'));
$('#addWebhook2').addEventListener('click',()=>toast('Webhook setup UI is a placeholder. Confirm signature verification with ZiiroPay first.'));
$('#usagePeriod').addEventListener('change',e=>toast('Chart preview: '+e.target.value+'. Connect production analytics to show real usage.'));

// The dashboard is deliberately a demo UI. Live provider calls are server-side only.
fetch('/api/health').then(r=>r.json()).then(data=>{
  if(data.providerConfigured){$('.env-pill').innerHTML='<i></i> '+(data.mode==='sandbox'?'Sandbox':'Production');}
}).catch(()=>{});
