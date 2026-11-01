import { useRef, useState } from 'react'
import {
  inspectFile, inspectPem, MAX_SOURCE_BYTES,
  type InspectResult, type TimeStatus,
} from './lib/certificates'

type InputMode = 'file' | 'paste'
type IconName = 'shield'|'upload'|'file'|'copy'|'download'|'reset'|'check'|'alert'|'github'|'arrow'|'lock'
const paths: Record<IconName,string> = {
  shield:'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z M9 12l2 2 4-4',
  upload:'M12 16V3m-5 5 5-5 5 5M4 16v4h16v-4',
  file:'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M8 13h8M8 17h6',
  copy:'M8 4H6a2 2 0 0 0-2 2v12h2M10 8h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2h-8a2 2 0 0 1-2-2V10a2 2 0 0 1 2-2Z',
  download:'M12 3v12m-5-5 5 5 5-5M4 18v3h16v-3',
  reset:'M3 11a9 9 0 1 1 2.5 6M3 4v7h7',
  check:'M5 12l4 4L19 6',
  alert:'M12 3 2 21h20L12 3ZM12 9v5m0 4h.01',
  github:'M9 19c-4.5 1.5-4.5-3-6-3M15 19c4.5 1.5 4.5-3 6-3M9 22v-3c-4-1-5-3-5-7 0-2 1-4 2-5-.5-1-1-3 0-4 2 0 3 1 4 2a14 14 0 0 1 4 0c1-1 2-2 4-2 1 1 .5 3 0 4 1 1 2 3 2 5 0 4-1 6-5 7v3',
  arrow:'M19 12H5m7-7-7 7 7 7',
  lock:'M5 11h14v11H5zM8 11V7a4 4 0 1 1 8 0v4',
}
function Icon({name,size=19}:{name:IconName;size?:number}){
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name]}/></svg>
}
const statusLabels: Record<TimeStatus,string> = {
  active:'در بازه زمانی اعتبار',
  soon:'نزدیک به پایان اعتبار',
  expired:'تاریخ اعتبار گذشته است',
  future:'هنوز معتبر از نظر تاریخ نیست',
  request:'درخواست صدور گواهی',
}
function formatDate(value: string | null) {
  if (!value) return '—'
  return new Intl.DateTimeFormat('fa-IR',{dateStyle:'long',timeStyle:'short'}).format(new Date(value))
}
function formatDays(days:number | null){
  if (days === null) return '—'
  if (days < 0) return Math.abs(days).toLocaleString('fa-IR') + ' روز از انقضا گذشته'
  return days.toLocaleString('fa-IR') + ' روز تا انقضا'
}
function publicReport(r:InspectResult){
  const { source:_source, ...safeReport } = r
  void _source
  return safeReport
}
function downloadReport(data:InspectResult[]){
  const file = new Blob([JSON.stringify({
    application:'CertLab',
    exportedAt:new Date().toISOString(),
    note:'Dates and CSR signatures are inspected locally. Trust chains and revocation are NOT checked.',
    results:data.map(publicReport),
  },null,2)], {type:'application/json;charset=utf-8'})
  const url = URL.createObjectURL(file)
  const link = document.createElement('a')
  link.href = url; link.download = 'CertLab-Report.json'
  document.body.appendChild(link); link.click(); link.remove()
  window.setTimeout(() => URL.revokeObjectURL(url),1500)
}
function DataField({label,value,mono=false}:{label:string;value:string|number|undefined|null;mono?:boolean}){
  return <div className="data-field"><span>{label}</span><strong dir={mono?'ltr':'auto'} className={mono?'mono-value':''}>{String(value ?? '—')}</strong></div>
}
export default function App(){
  const fileInput=useRef<HTMLInputElement>(null)
  const [mode,setMode]=useState<InputMode>('file')
  const [text,setText]=useState('')
  const [fileName,setFileName]=useState('')
  const [dragging,setDragging]=useState(false)
  const [working,setWorking]=useState(false)
  const [reports,setReports]=useState<InspectResult[]>([])
  const [selected,setSelected]=useState(0)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const current=reports[selected] ?? null

  function reset(){
    setReports([]); setSelected(0);setError('');setNotice('');setText('');setFileName('')
    if(fileInput.current)fileInput.current.value=''
  }
  async function handleFile(file:File|undefined){
    if(!file)return
    setError('');setNotice('');setReports([]);setSelected(0);setFileName(file.name)
    if(file.size>MAX_SOURCE_BYTES){setError('حجم هر ورودی باید حداکثر ۲ مگابایت باشد.');return}
    setWorking(true)
    try {
      const result=await inspectFile(file)
      setReports(result);setSelected(0)
      setNotice(result.length.toLocaleString('fa-IR')+' مورد با موفقیت تحلیل شد.')
    }catch(e){setError(e instanceof Error?e.message:'تحلیل فایل انجام نشد.')}
    finally{setWorking(false);if(fileInput.current)fileInput.current.value=''}
  }
  async function handlePaste(){
    if(!text.trim()){setError('لطفاً محتوای PEM یا CSR را وارد کنید.');return}
    setWorking(true);setError('');setNotice('');setReports([]);setSelected(0);setFileName('PEM / TEXT')
    try{
      const result=await inspectPem(text)
      setReports(result);setNotice(result.length.toLocaleString('fa-IR')+' مورد با موفقیت تحلیل شد.')
    }catch(e){setError(e instanceof Error?e.message:'محتوای PEM قابل تحلیل نیست.')}
    finally{setWorking(false)}
  }
  async function copy(value:string){
    try {await navigator.clipboard.writeText(value);setNotice('در حافظه کپی شد.');setError('')}
    catch {setError('دسترسی به Clipboard ممکن نشد؛ از روش کپی دستی استفاده کنید.')}
  }
  return <main className="app-shell">
    <div className="grid-background" aria-hidden="true"/>
    <div className="ambient ambient-emerald" aria-hidden="true"/>
    <div className="ambient ambient-blue" aria-hidden="true"/>

    <header className="topbar">
      <div className="brand-lockup"><span className="brand-mark"><Icon name="shield" size={21}/></span><div className="brand-copy"><span className="brand">سرت‌لب</span><span className="brand-en" dir="ltr">CERTLAB</span></div></div>
      <div className="topbar-right">
        <div className="product-status" dir="ltr"><span className="status-dot"/>LOCAL / PRIVATE<span className="status-divider">·</span>V1.0</div>
        <a className="header-link" href="https://github.com/Mehrdad32/CertLab" target="_blank" rel="noreferrer" aria-label="مشاهده سورس در GitHub" title="GitHub"><Icon name="github" size={18}/></a>
      </div>
    </header>

    <section className="hero">
      <div className="eyebrow" dir="ltr"><span className="eyebrow-line"/> X.509 / TLS / PKCS#10 ANALYZER</div>
      <h1>گواهی SSL، <span>زیر ذره‌بین.</span></h1>
      <p>گواهی دیجیتال یا درخواست CSR را وارد کنید و جزئیات فنی آن را ببینید؛ از زمان اعتبار و SAN تا الگوریتم امضا، کلید عمومی و اثر انگشت SHA-256.</p>
    </section>

    <section className="workspace" aria-label="ورودی و گزارش گواهی">
      <div className="panel source-panel">
        <div className="panel-header">
          <div><span className="panel-label">مرحله ۰۱ · ورودی محلی</span><h2>بررسی گواهی</h2></div>
          <span className="panel-code">LOCAL / INPUT</span>
        </div>
        <div className="tabs" role="tablist" aria-label="روش ورود داده">
          <button type="button" role="tab" aria-selected={mode==='file'} className={mode==='file'?'active':''} onClick={()=>{reset();setMode('file')}}>انتخاب فایل</button>
          <button type="button" role="tab" aria-selected={mode==='paste'} className={mode==='paste'?'active':''} onClick={()=>{reset();setMode('paste')}}>متن PEM</button>
        </div>
        {mode==='file'?<>
          <input ref={fileInput} className="sr-only" type="file" accept=".pem,.crt,.cer,.csr,.der,.txt" aria-label="انتخاب گواهی یا CSR" onChange={e=>void handleFile(e.target.files?.[0])}/>
          <div className={'dropzone'+(dragging?' dragging':'')}
            onDragOver={e=>{e.preventDefault();setDragging(true)}}
            onDragLeave={e=>{e.preventDefault();setDragging(false)}}
            onDrop={e=>{e.preventDefault();setDragging(false);void handleFile(e.dataTransfer.files[0])}}>
            <span className="upload-icon"><Icon name="upload" size={27}/></span>
            <strong>فایل گواهی را اینجا رها کنید</strong>
            <span>یا از رایانه و موبایل انتخاب کنید</span>
            <button type="button" className="secondary-btn" onClick={()=>fileInput.current?.click()}>انتخاب Certificate / CSR</button>
            <small dir="ltr">.PEM · .CRT · .CER · .CSR · .DER</small>
          </div>
          {fileName&&<div className="input-file"><Icon name="file"/><span dir="auto">{fileName}</span><button type="button" onClick={reset} aria-label="پاک کردن"><Icon name="reset" size={16}/></button></div>}
        </>:<>
          <label className="paste-label" htmlFor="pem-paste">متن گواهی یا CSR با قالب PEM</label>
          <textarea id="pem-paste" spellCheck={false} dir="ltr" placeholder={'-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----'} value={text} onChange={e=>{setText(e.target.value);setReports([]);setError('');setNotice('')}} maxLength={MAX_SOURCE_BYTES} />
          <button type="button" className="primary-btn" onClick={()=>void handlePaste()} disabled={working||!text.trim()}>{working?'در حال تحلیل…':'تحلیل متن PEM'}<Icon name="arrow" size={17}/></button>
        </>}
        {working&&<div className="loading-line" role="status">در حال پردازش محلی داده‌ها…</div>}
        {error&&<div className="message error" role="alert"><Icon name="alert" size={17}/>{error}</div>}
        {notice&&!error&&<div className="message success" role="status"><Icon name="check" size={17}/>{notice}</div>}
        <div className="input-footer">
          <div className="privacy-label"><Icon name="lock" size={16}/><b>هیچ فایلی آپلود نمی‌شود.</b></div>
          <p>همه پردازش‌ها در مرورگر انجام می‌شوند. کلید خصوصی و فایل PFX/P12 پذیرفته نمی‌شوند. محدودیت ورودی: ۲ مگابایت.</p>
        </div>
      </div>

      <div className="panel result-panel">
        <div className="panel-header">
          <div><span className="panel-label">مرحله ۰۲ · گزارش فنی</span><h2>جزئیات Certificate</h2></div>
          <span className="panel-code result-code">X.509 / REPORT</span>
        </div>
        {!current?<div className="empty-result"><div className="empty-emblem"><Icon name="shield" size={41}/></div><strong>آماده تحلیل گواهی</strong><p>یک فایل CRT، PEM، CER یا CSR انتخاب کنید تا مشخصات آن اینجا نمایش داده شود.</p><span>NO DATA / WAITING FOR INPUT</span></div>:<>
          {reports.length>1&&<div className="entry-picker">
            <label htmlFor="entry-select">گواهی‌های داخل فایل ({reports.length.toLocaleString('fa-IR')})</label>
            <select id="entry-select" value={selected} onChange={e=>setSelected(Number(e.target.value))}>{reports.map((r,i)=><option key={r.id} value={i}>{i+1}. {r.label} ({r.kind==='csr'?'CSR':'Certificate'})</option>)}</select>
          </div>}
          <div className="report-summary">
            <div className="report-heading"><span className="report-type">{current.kind==='csr'?'CERTIFICATE REQUEST':'X.509 CERTIFICATE'}</span><span className={'status-pill '+current.timeStatus}>{statusLabels[current.timeStatus]}</span></div>
            <h3 dir="auto">{current.label}</h3>
            <div className="report-subtitle">{current.kind==='csr'?'درخواست امضای گواهی (PKCS#10)':'ارزیابی تاریخ گواهی؛ نه زنجیره اعتماد یا وضعیت ابطال'}</div>
            <div className="summary-stats">
              <div><span>نوع</span><b dir="ltr">{current.kind==='csr'?'CSR':'X.509'}</b></div>
              <div><span>{current.kind==='csr'?'امضای CSR':'باقی‌مانده اعتبار'}</span><b>{current.kind==='csr'?(current.csrSignatureVerified===true?'تأیید شد':current.csrSignatureVerified===false?'نامعتبر':'بررسی نشد'):formatDays(current.daysRemaining)}</b></div>
            </div>
          </div>
          <div className="report-toolbar">
            <button type="button" onClick={()=>void copy(current.sha256)}><Icon name="copy" size={15}/> کپی اثر انگشت</button>
            <button type="button" onClick={()=>downloadReport(reports)}><Icon name="download" size={15}/> خروجی JSON</button>
            <button type="button" onClick={reset}><Icon name="reset" size={15}/> پاک کردن</button>
          </div>
          <div className="details-scroll">
            <div className="section-title">هویت گواهی <span>IDENTITY</span></div>
            <div className="data-grid">
              <DataField label="Subject / مالک" value={current.subject} mono/>
              {current.issuer&&<DataField label="Issuer / صادرکننده" value={current.issuer} mono/>}
              {current.serial&&<DataField label="Serial Number" value={current.serial} mono/>}
              {current.selfIssued&&<DataField label="وضعیت صدور" value="Subject و Issuer یکسان‌اند؛ اعتماد یا امضا تأیید نشده است."/>}
            </div>

            {current.kind==='certificate'&&<>
              <div className="section-title">بازه اعتبار <span>VALIDITY</span></div>
              <div className="data-grid two">
                <DataField label="شروع اعتبار" value={formatDate(current.notBefore)}/>
                <DataField label="پایان اعتبار" value={formatDate(current.notAfter)}/>
              </div>
            </>}
            <div className="section-title">رمزنگاری <span>CRYPTOGRAPHY</span></div>
            <div className="data-grid">
              <DataField label="الگوریتم امضا" value={current.signatureAlgorithm} mono/>
              <DataField label="کلید عمومی" value={current.publicKeyAlgorithm} mono/>
              <div className="data-field fingerprint-field"><span>SHA-256 Fingerprint {current.kind==='csr'?'(CSR DER)':'(Certificate DER)'}</span><strong dir="ltr" className="fingerprint-value">{current.sha256}</strong><button type="button" className="mini-copy" onClick={()=>void copy(current.sha256)} aria-label="کپی اثر انگشت"><Icon name="copy" size={14}/></button></div>
            </div>
            <div className="section-title">نام‌های جایگزین <span>SAN</span></div>
            <div className="chips">
              {current.sans.length?current.sans.map((san,i)=><span key={i} className="chip" dir="ltr"><small>{san.kind}</small>{san.value}</span>):<div className="no-data">فیلد SAN در ورودی موجود نیست یا قابل خواندن نیست.</div>}
            </div>
            <div className="section-title">ویژگی‌ها <span>EXTENSIONS</span></div>
            <div className="data-grid two">
              <DataField label="Certificate Authority" value={current.ca===null?'نامشخص':current.ca?'CA: TRUE':'CA: FALSE'}/>
              <DataField label="تعداد افزونه‌ها" value={current.extensions.length.toLocaleString('fa-IR')}/>
            </div>
            {current.keyUsages.length>0&&<div className="extension-group"><span>Key Usage</span><div className="chips">{current.keyUsages.map(x=><span key={x} className="chip">{x}</span>)}</div></div>}
            {current.extendedKeyUsages.length>0&&<div className="extension-group"><span>Extended Key Usage</span><div className="chips">{current.extendedKeyUsages.map(x=><span key={x} className="chip">{x}</span>)}</div></div>}
            <details className="extension-details"><summary>نمایش تمامی Extensionها ({current.extensions.length})</summary><div className="extension-list">{current.extensions.length?current.extensions.map((e,i)=><div key={i}><b>{e.name}</b><code dir="ltr">{e.oid}</code>{e.critical&&<small>Critical</small>}</div>):<p>افزونه‌ای وجود ندارد.</p>}</div></details>
          </div>
        </>}
      </div>
    </section>
    <section className="trust-bar">
      <div><span><Icon name="lock"/></span><b>کاملاً خصوصی</b><small>بدون ارسال فایل به سرور</small></div>
      <div><span><Icon name="file"/></span><b>Certificate و CSR</b><small>پشتیبانی از PEM و DER</small></div>
      <div><span><Icon name="shield"/></span><b>تحلیل دقیق</b><small>زمان اعتبار، SAN و SHA-256</small></div>
    </section>
    <div className="safety-note"><Icon name="alert" size={19}/><p><strong>نکته امنیتی:</strong> اعتبار زمانی یا تأیید امضای CSR به معنی اعتماد مرورگر به گواهی نیست. بررسی زنجیره اعتماد، نام میزبان، وضعیت ابطال (OCSP/CRL) و اتصال زنده سرور در این ابزار انجام نمی‌شود.</p></div>
    <footer className="footer"><span>CertLab · ساخته‌شده توسط <a href="https://mehrdad32.ir/" target="_blank" rel="noreferrer">Mehrdad32</a></span><div><a href="https://github.com/Mehrdad32/CertLab" target="_blank" rel="noreferrer">GITHUB / SOURCE</a><span>·</span><a href="https://mehrdad32.ir/fa/projects" target="_blank" rel="noreferrer">سایر پروژه‌ها</a></div></footer>
  </main>
}
