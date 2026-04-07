// ===== データ =====
const VEHICLES = ['電動キックボード', '電動自転車', 'ハマー', 'e-bike'];
const VEHICLE_IDS = { '電動キックボード': 'kickboard', '電動自転車': 'ebicycle', 'ハマー': 'hummer', 'e-bike': 'ebike' };

const CHECKLIST = [
  {
    section: '走行機能',
    icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4l3 3"/></svg>',
    items: [
      { id: 'brake_front', name: '前ブレーキ', note: '効き具合の確認', refImage: 'assets/ref_brake.jpg' },
      { id: 'brake_rear', name: '後ブレーキ', note: '効き具合の確認', refImage: 'assets/ref_brake.jpg' },
      { id: 'brake_wire', name: 'ブレーキワイヤー', note: 'ほつれ・錆・損傷の確認', refImage: 'assets/ref_wire.jpg' },
      { id: 'tire_air', name: 'タイヤの空気圧', note: '指で押して凹まないか', refImage: 'assets/ref_tire_press.jpg' },
      { id: 'tire_condition', name: 'タイヤの状態', note: '摩耗・亀裂・異物がないか', refImage: 'assets/ref_tire_cond.jpg' },
      { id: 'rim_spoke', name: 'リム・スポーク', note: '変形・緩みの確認', refImage: 'assets/ref_rim.jpg' },
    ]
  },
  {
    section: '安全装備',
    icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    items: [
      { id: 'light_front', name: 'フロントライト', note: '点灯するか確認', refImage: 'assets/ref_light.jpg' },
      { id: 'light_rear', name: 'リアライト・反射板', note: '点灯・汚れ・破損の確認', refImage: 'assets/ref_light_rear.jpg' },
      { id: 'reflector_side', name: 'サイド反射板', note: '有無・破損の確認', refImage: 'assets/ref_reflector.jpg' },
      { id: 'bell', name: 'ベル', note: '音が鳴るか確認', refImage: 'assets/ref_bell.jpg' },
      { id: 'handle_tight', name: 'ハンドルのガタつき', note: '緩みや振れがないか', refImage: 'assets/ref_handle.jpg' },
      { id: 'mirror', name: 'バックミラー', note: '固定・視界の確認（キックボード等）', refImage: 'assets/ref_mirror.jpg' },
    ]
  },
  {
    section: '車体・駆動',
    icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>',
    items: [
      { id: 'chain', name: 'チェーン・駆動系', note: 'サビ・緩み・汚れの確認', refImage: 'assets/ref_chain.jpg' },
      { id: 'saddle', name: 'サドルの固定', note: '動かないように締まっているか', refImage: 'assets/ref_saddle.jpg' },
      { id: 'pedal', name: 'ペダル', note: 'ガタつき・回転の確認', refImage: 'assets/ref_pedal.jpg' },
      { id: 'kickstand', name: 'スタンド', note: 'バネ・固定の確認', refImage: 'assets/ref_kickstand.jpg' },
      { id: 'battery', name: 'バッテリー・配線', note: '固定・端子の汚れ確認（電動車両）', refImage: 'assets/ref_battery.jpg' },
      { id: 'overall_look', name: '全体の傷・汚れ', note: '目立つ損傷がないか', refImage: 'assets/ref_overall.jpg' },
    ]
  }
];

// 各車両セクション除外（電装系はキックボード・電動自転車・e-bikeのみ、ハマーは無し）
const VEHICLE_SKIP_SECTIONS = {
  'ハマー': ['電装系（電動車両のみ）'],
};

// ===== セキュリティ・暗号化設定 =====
const SESSION = {
  isLocked: true,
  pinHash: localStorage.getItem('app_pin_hash'), // SHA-256
  salt: localStorage.getItem('app_salt') || crypto.getRandomValues(new Uint8Array(16)).join(','),
  key: null, // AES-GCM CryptoKey (メモリ内のみ保持)
  cache: {
    inspections: [],
    settings: {
      approverEmail: '',
      approverName: '',
      approvalPin: '1234', // 助役用内部PIN（旧仕様互換）
      powerAutomateUrl: '',
      autoLockMinutes: 5
    },
    vehicleNumbers: {},
    tirePressures: {},
    activeItems: {},
    customItems: [],
    refPhotos: {}
  }
};
if (!localStorage.getItem('app_salt')) localStorage.setItem('app_salt', SESSION.salt);

// ===== 暗号化ユーティリティ (Web Crypto API) =====
async function deriveKey(pin) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: new TextEncoder().encode(SESSION.salt), iterations: 100000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encrypt(data, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(data));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return btoa(String.fromCharCode(...combined));
}

async function decrypt(base64, key) {
  const combined = new Uint8Array(atob(base64).split('').map(c => c.charCodeAt(0)));
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return JSON.parse(new TextDecoder().decode(decrypted));
}

async function hashPin(pin) {
  const msgUint8 = new TextEncoder().encode(pin + SESSION.salt);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ===== データ永続化 (暗号化対応キャッシュ) =====
function getData() { return SESSION.cache.inspections; }
function saveData(data) { SESSION.cache.inspections = data; persist('inspections'); }
function getSettings() { return SESSION.cache.settings; }
function saveSettingsData(s) { SESSION.cache.settings = s; persist('settings'); }
function getVehicleNumbers() { return SESSION.cache.vehicleNumbers; }
function saveVehicleNumbersData(d) { SESSION.cache.vehicleNumbers = d; persist('vehicleNumbers'); }
function getTirePressures() { return SESSION.cache.tirePressures; }
function saveTirePressuresData(d) { SESSION.cache.tirePressures = d; persist('tirePressures'); }
function getActiveItems() { return SESSION.cache.activeItems; }
function saveActiveItemsData(d) { SESSION.cache.activeItems = d; persist('activeItems'); }
function getRefPhotos() { return SESSION.cache.refPhotos; }
function saveRefPhotosData(d) { SESSION.cache.refPhotos = d; persist('refPhotos'); }
function getCustomItems() { return SESSION.cache.customItems; }
function saveCustomItemsData(d) { SESSION.cache.customItems = d; persist('customItems'); }

async function persist(key) {
  if (SESSION.isLocked || !SESSION.key) return;
  try {
    const encrypted = await encrypt(SESSION.cache[key], SESSION.key);
    localStorage.setItem(`enc_${key}`, encrypted);
  } catch (e) { console.error('Persistence failed:', e); }
}

// ===== ロック画面・ログイン・自動移行 =====
let lockPinInput = '';
function updatePinDots() {
  for (let i = 1; i <= 4; i++) {
    document.getElementById('dot-' + i).classList.toggle('filled', i <= lockPinInput.length);
  }
}

async function pressKey(key) {
  if (key === 'back') {
    lockPinInput = lockPinInput.slice(0, -1);
  } else if (lockPinInput.length < 4) {
    lockPinInput += key;
  }
  updatePinDots();
  if (lockPinInput.length === 4) {
    await attemptUnlock(lockPinInput);
    lockPinInput = '';
    setTimeout(updatePinDots, 200);
  }
}

async function attemptUnlock(pin) {
  const errorMsg = document.getElementById('lock-error-msg');
  errorMsg.style.visibility = 'hidden';

  // 初回設定時
  if (!SESSION.pinHash) {
    if (confirm('この番号を新しい暗証番号として設定しますか？\n（忘れるとデータを復旧できません）')) {
      SESSION.pinHash = await hashPin(pin);
      localStorage.setItem('app_pin_hash', SESSION.pinHash);
      SESSION.key = await deriveKey(pin);
      SESSION.isLocked = false;
      document.getElementById('app-lock-screen').classList.remove('active');
      // 既存データの移行
      await migrateOldData(SESSION.key);
      showToast('暗証番号を設定し、データを保護しました', 'success');
      showPage('dashboard');
    }
    return;
  }

  // 通常解除
  const enteredHash = await hashPin(pin);
  if (enteredHash === SESSION.pinHash) {
    try {
      SESSION.key = await deriveKey(pin);
      await loadAllEncryptedData(SESSION.key);
      SESSION.isLocked = false;
      document.getElementById('app-lock-screen').classList.remove('active');
      updateDashboard();
      showToast('ロックを解除しました', 'success');
      resetAutoLockTimer();
    } catch (e) {
      console.error(e);
      errorMsg.textContent = '復号に失敗しました。正しいPINを入力してください。';
      errorMsg.style.visibility = 'visible';
    }
  } else {
    errorMsg.style.visibility = 'visible';
    // 軽いバイブレーション演出などがあれば良いが、とりあえずエラー表示のみ
  }
}

async function loadAllEncryptedData(key) {
  const keys = ['inspections', 'settings', 'vehicleNumbers', 'tirePressures', 'activeItems', 'customItems', 'refPhotos'];
  for (const k of keys) {
    const enc = localStorage.getItem('enc_' + k);
    if (enc) {
      SESSION.cache[k] = await decrypt(enc, key);
    }
  }
}

// 既存の平文データがあれば暗号化して移行
async function migrateOldData(key) {
  const oldKeys = ['inspections', 'settings', 'vehicleNumbers', 'tirePressures', 'app_active_items', 'app_custom_items', 'app_ref_photos'];
  const map = {
    'inspections': 'inspections',
    'settings': 'settings',
    'vehicleNumbers': 'vehicleNumbers',
    'tirePressures': 'tirePressures',
    'app_active_items': 'activeItems',
    'app_custom_items': 'customItems',
    'app_ref_photos': 'refPhotos'
  };
  
  for (const old of oldKeys) {
    const val = localStorage.getItem(old);
    if (val) {
      try {
        SESSION.cache[map[old]] = JSON.parse(val);
        await persist(map[old]);
        localStorage.removeItem(old); // 元の平文を削除
      } catch(e) { console.warn('Migration failed for ' + old, e); }
    }
  }
}

// 自動ロック
let autoLockTimer;
function resetAutoLockTimer() {
  clearTimeout(autoLockTimer);
  if (SESSION.isLocked) return;
  const mins = SESSION.cache.settings.autoLockMinutes || 5;
  if (mins === 0) return; // ロックなし設定
  autoLockTimer = setTimeout(lockApp, mins * 60 * 1000);
}

function lockApp() {
  SESSION.isLocked = true;
  SESSION.key = null; // メモリから鍵を抹消
  document.getElementById('app-lock-screen').classList.add('active');
}

window.addEventListener('mousedown', resetAutoLockTimer);
window.addEventListener('touchstart', resetAutoLockTimer);
window.addEventListener('keydown', resetAutoLockTimer);

// 初期ロード
window.addEventListener('DOMContentLoaded', () => {
  if (!SESSION.pinHash) {
    // 初回起動時もロック画面を表示（PIN設定を促す）
    document.getElementById('app-lock-screen').classList.add('active');
  }
});

// ===== ページ切替 =====
function showPage(pageId) {
  document.querySelectorAll('.page').forEach(p => p.style.display = 'none');
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  const page = document.getElementById('page-' + pageId);
  if (page) page.style.display = 'block';
  const navBtn = document.getElementById('nav-' + pageId);
  if (navBtn) navBtn.classList.add('active');

  if (pageId === 'dashboard') updateDashboard();
  if (pageId === 'history') renderHistory();
  if (pageId === 'approval') renderApprovalPage();
  if (pageId === 'settings') loadSettings();
  updateApprovalBadge();
}

// ===== ダッシュボード =====
function updateDashboard() {
  const data = getData();
  const now = new Date();
  document.getElementById('current-date').textContent =
    now.getFullYear() + '年' + (now.getMonth()+1) + '月' + now.getDate() + '日（' +
    ['日','月','火','水','木','金','土'][now.getDay()] + '）';

  document.getElementById('stat-total').textContent = data.length;
  document.getElementById('stat-pending').textContent = data.filter(d=>d.status==='pending').length;
  document.getElementById('stat-approved').textContent = data.filter(d=>d.status==='approved').length;
  document.getElementById('stat-rejected').textContent = data.filter(d=>d.status==='rejected').length;

  VEHICLES.forEach(v => {
    const id = VEHICLE_IDS[v];
    const el = document.getElementById('vc-' + id);
    if (el) el.textContent = data.filter(d=>d.vehicle===v).length + '件';
  });

  const recent = [...data].sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)).slice(0,5);
  const container = document.getElementById('recent-inspections');
  if (recent.length === 0) {
    container.innerHTML = `<div class="empty-state"><svg viewBox="0 0 64 64" fill="none"><circle cx="32" cy="32" r="28" stroke="#FF6B00" stroke-width="2" opacity="0.3"/><path d="M20 32 L28 40 L44 24" stroke="#FF6B00" stroke-width="3" stroke-linecap="round" opacity="0.3"/></svg><p>点検データがありません<br>「新規点検」から始めてください</p></div>`;
  } else {
    container.innerHTML = recent.map(d => `
      <div class="inspection-item" onclick="openInspectionDetail('${d.id}')">
        <div class="item-vehicle-icon">${getVehicleSVG(d.vehicle)}</div>
        <div class="item-info">
          <div class="item-title">${d.vehicle}　${d.vehicleNumber ? '【' + d.vehicleNumber + '】' : ''}</div>
          <div class="item-sub">点検者: ${d.inspectorName || '未記入'} ／ ${formatDate(d.createdAt)}</div>
        </div>
        <div class="item-actions">
          <span class="status-badge ${statusClass(d.status)}">${statusLabel(d.status)}</span>
        </div>
      </div>`).join('');
  }
}

// ===== 車両選択 =====
function selectVehicle(name, el) {
  document.querySelectorAll('.vehicle-card').forEach(c => c.classList.remove('selected'));
  el.classList.add('selected');
  selectedVehicle = name;
  document.getElementById('btn-step1-next').disabled = false;
}

// ===== 天候選択 =====
function selectWeather(w, el) {
  document.querySelectorAll('.weather-btn').forEach(b => b.classList.remove('selected'));
  el.classList.add('selected');
  selectedWeather = w;
}

// ===== ステップ管理 =====
function goToStep(step) {
  if (step === 2) {
    if (!selectedVehicle) { showToast('車両を選択してください', 'error'); return; }
    setStepDate();
    
    // 車両番号候補の更新
    const vnData = getVehicleNumbers();
    const list = document.getElementById('vehicle-numbers-list');
    if (list) {
      const numbers = vnData[selectedVehicle] ? vnData[selectedVehicle].split(',').map(s => s.trim()).filter(s => s) : [];
      list.innerHTML = numbers.map(n => `<option value="${n}">`).join('');
    }
  }
  if (step === 3) {
    const name = document.getElementById('inspector-name').value.trim();
    if (!name) { showToast('点検者名を入力してください', 'error'); return; }
    buildChecklist();
  }
  if (step === 4) {
    buildSummary();
    const settings = getSettings();
    document.getElementById('display-approver-email').textContent =
      settings.approverEmail ? (settings.approverName || '助役') + ' <' + settings.approverEmail + '>' : '設定から承認者メールを設定してください';
  }

  for (let i = 1; i <= 4; i++) {
    const stepEl = document.getElementById('form-step-' + i);
    if (stepEl) stepEl.style.display = i === step ? 'block' : 'none';
    const ind = document.getElementById('step-' + i + '-ind');
    if (ind) ind.className = 'step' + (i === step ? ' active' : i < step ? ' done' : '');
  }
  currentStep = step;
}

function setStepDate() {
  const el = document.getElementById('inspection-date');
  if (!el.value) {
    const now = new Date();
    const pad = n => String(n).padStart(2,'0');
    el.value = now.getFullYear()+'-'+pad(now.getMonth()+1)+'-'+pad(now.getDate())+'T'+pad(now.getHours())+':'+pad(now.getMinutes());
  }
}

// ===== 写真機能 =====
function triggerPhoto(itemId) {
  const input = document.getElementById('photo-input');
  input.onchange = (e) => handlePhotoSelect(e, itemId);
  input.click();
}

function handlePhotoSelect(event, itemId) {
  const file = event.target.files[0];
  if (!file) return;

  showToast('写真を圧縮中...', 'success');
  compressImage(file, (base64) => {
    const container = document.querySelector(`#ci-${itemId} .checklist-photo-area`);
    let preview = container.querySelector('.photo-preview-container');
    
    if (!preview) {
      preview = document.createElement('div');
      preview.className = 'photo-preview-container';
      container.appendChild(preview);
    }
    
    preview.innerHTML = `
      <img src="${base64}" class="photo-preview" onclick="viewPhoto('${base64}')">
      <button class="btn-remove-photo" onclick="removePhoto('${itemId}')">✕</button>
    `;
    event.target.value = '';
    showToast('写真を追加しました', 'success');
  });
}

function compressImage(file, callback) {
  const reader = new FileReader();
  reader.onload = (e) => {
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      let width = img.width;
      let height = img.height;
      const max = 600;

      if (width > height) {
        if (width > max) { height *= max / width; width = max; }
      } else {
        if (height > max) { width *= max / height; height = max; }
      }

      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0, width, height);
      callback(canvas.toDataURL('image/jpeg', 0.6));
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

function removePhoto(itemId) {
  const container = document.querySelector(`#ci-${itemId} .checklist-photo-area`);
  const preview = container.querySelector('.photo-preview-container');
  if (preview) preview.remove();
}

function viewReferencePhoto(itemId) {
  let itemFound = null;
  CHECKLIST.forEach(s => {
    const found = s.items.find(it => it.id === itemId);
    if (found) itemFound = found;
  });
  if (!itemFound) return;

  const modal = document.getElementById('modal-overlay');
  const content = document.getElementById('modal-content');
  
  const refPhotos = getRefPhotos();
  const vehicleRefs = refPhotos[selectedVehicle] || {};
  const displayImg = vehicleRefs[itemId] || itemFound.refImage;
  
  content.innerHTML = `
    <div style="text-align:center; padding: 20px;">
      <h3 style="margin-bottom:15px; color:var(--orange)">点検箇所確認：${itemFound.name}</h3>
      <div style="background:var(--gray-800); border-radius:12px; overflow:hidden; margin-bottom:15px; border:1px solid rgba(255,107,0,0.3)">
        <img src="${displayImg}" style="width:100%; height:auto; display:block;" onerror="this.outerHTML='<div style=\'padding:60px; color:var(--gray-400)\'>画像準備中<br><small>正解イメージが表示されます</small></div>'">
      </div>
      <p style="font-size:14px; color:var(--gray-300); line-height:1.6">${itemFound.note}</p>
      <button class="btn-primary" style="margin-top:20px; width:100%" onclick="closeModal()">確認しました</button>
    </div>
  `;
  modal.classList.add('active');
}

function viewPhoto(base64) {
  const div = document.createElement('div');
  div.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.9);z-index:1000;display:flex;align-items:center;justify-content:center;padding:20px;cursor:pointer;';
  div.innerHTML = `<img src="${base64}" style="max-width:100%;max-height:100%;border-radius:8px;box-shadow:0 0 40px rgba(0,0,0,0.5)">`;
  div.onclick = () => div.remove();
  document.body.appendChild(div);
}

// ===== チェックリスト構築 =====
function buildChecklist() {
  const skip = VEHICLE_SKIP_SECTIONS[selectedVehicle] || [];
  const container = document.getElementById('checklist-container');
  container.innerHTML = '';

  const refPhotos = getRefPhotos();
  const vehicleRefs = refPhotos[selectedVehicle] || {};
  const tirePressures = getTirePressures();
  const recommendedPressure = tirePressures[selectedVehicle] || '';
  const activeItemsData = getActiveItems();
  const activeItems = activeItemsData[selectedVehicle] || null;
  const customItems = getCustomItems();

  CHECKLIST.forEach(section => {
    // 固定項目とカスタム項目を結合
    const sectionItems = [...section.items, ...customItems.filter(ci => ci.section === section.section)];
    
    // 1つでも有効な項目があるセクションのみ描画
    const itemsToRender = sectionItems.filter(it => activeItems ? activeItems.includes(it.id) : true);
    if (itemsToRender.length === 0) return;

    const sec = document.createElement('div');
    sec.className = 'checklist-section';
    
    sec.innerHTML = `
      <div class="checklist-section-header">
        ${section.icon}
        ${section.section}
      </div>` +
      itemsToRender.map(item => {
        const displayImg = vehicleRefs[item.id] || item.refImage;
        const itemName = (item.id === 'tire_air' && recommendedPressure) 
          ? `${item.name} <span style="color:var(--orange); font-size:0.9em; margin-left:8px;">(推奨: ${recommendedPressure})</span>`
          : item.name;

        return `
        <div class="checklist-item" id="ci-${item.id}">
          <div class="checklist-item-name">
            ${itemName}
            <span>${item.note}</span>
          </div>
          <div class="check-options">
            <button class="check-btn ok" onclick="selectCheck('${item.id}','ok',this)">✅ 良好</button>
            <button class="check-btn warn" onclick="selectCheck('${item.id}','warn',this)">➖ 点検不要・対象外</button>
            <button class="check-btn ng" onclick="selectCheck('${item.id}','ng',this)">❌ 不良</button>
          </div>
          <div class="checklist-ref-area">
            <div class="ref-thumb" onclick="viewReferencePhoto('${item.id}')">
              <img src="${displayImg}" id="ref-img-${item.id}" onerror="this.outerHTML='<span style=\'padding:4px\'>点検箇所<br>確認</span>'" alt="参考">
            </div>
            <div class="ref-info">
              <span class="ref-info-title">点検箇所確認</span>
              <span class="ref-info-desc">${item.note}</span>
            </div>
            <button class="btn-view-ref" onclick="viewReferencePhoto('${item.id}')">拡大</button>
          </div>
          <div class="checklist-item-comment">
            <input type="text" id="comment-${item.id}" placeholder="メモ">
            <div class="checklist-photo-area">
              <button class="btn-add-photo" onclick="triggerPhoto('${item.id}')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>
                点検写真を追加
              </button>
            </div>
          </div>
        </div>`;
      }).join('');
    container.appendChild(sec);
  });
}

function selectCheck(itemId, status, btn) {
  const parent = btn.closest('.check-options');
  if (parent) {
    parent.querySelectorAll('.check-btn').forEach(b => { b.classList.remove('selected'); });
    btn.classList.add('selected');
  }
}

// ===== 点検データ収集 =====
function collectChecklistData() {
  const results = {};
  const skip = VEHICLE_SKIP_SECTIONS[selectedVehicle] || [];
  CHECKLIST.forEach(section => {
    if (skip.includes(section.section)) return;
    section.items.forEach(item => {
      const selected = document.querySelector(`#ci-${item.id} .check-btn.selected`);
      const commentInput = document.getElementById('comment-' + item.id);
      const photoPreview = document.querySelector(`#ci-${item.id} .photo-preview`);
      results[item.id] = {
        name: item.name,
        section: section.section,
        status: selected ? selected.classList[1] : 'none',
        comment: commentInput ? commentInput.value : '',
        photo: photoPreview ? photoPreview.src : null
      };
    });
  });
  return results;
}

// ===== サマリー構築 =====
function buildSummary() {
  const checks = collectChecklistData();
  let ok = 0, warn = 0, ng = 0, none = 0;
  Object.values(checks).forEach(c => {
    if (c.status==='ok') ok++;
    else if (c.status==='warn') warn++;
    else if (c.status==='ng') ng++;
    else none++;
  });

  const vehicle = selectedVehicle;
  const inspector = document.getElementById('inspector-name').value;
  const date = document.getElementById('inspection-date').value;
  const vNum = document.getElementById('vehicle-number').value;
  const loc = document.getElementById('inspection-location').value;

  document.getElementById('completion-summary').innerHTML = `
    <div class="summary-header">
      <div style="width:70px;height:50px">${getVehicleSVG(vehicle)}</div>
      <div>
        <h3>${vehicle} ${vNum ? '【' + vNum + '】' : ''}</h3>
        <p style="color:var(--gray-400);font-size:13px">点検者: ${inspector} ／ ${date ? date.replace('T',' ') : '未設定'} ／ ${loc || '場所未記入'}</p>
      </div>
    </div>
    <div class="summary-grid">
      <div class="summary-item"><div class="s-value s-ok">${ok}</div><div class="s-label">良好</div></div>
      <div class="summary-item"><div class="s-value s-warn">${warn}</div><div class="s-label">要注意</div></div>
      <div class="summary-item"><div class="s-value s-ng">${ng}</div><div class="s-label">不良</div></div>
    </div>
    ${ng > 0 ? `<div style="padding:10px 14px;background:rgba(231,76,60,0.1);border-radius:8px;border:1px solid rgba(231,76,60,0.3);font-size:13px;color:var(--red)">⚠️ 不良項目が ${ng} 件あります。承認依頼前に確認してください。</div>` : ''}
    ${none > 0 ? `<div style="padding:10px 14px;background:rgba(243,156,18,0.1);border-radius:8px;border:1px solid rgba(243,156,18,0.3);font-size:13px;color:var(--yellow);margin-top:8px">📋 未チェック項目が ${none} 件あります。</div>` : ''}
  `;
}

// ===== 保存 =====
function saveAsDraft() {
  saveInspection('draft');
}

function submitInspection() {
  const settings = getSettings();
  if (!settings.approverEmail) {
    showToast('先に設定から承認者のメールアドレスを設定してください', 'error'); return;
  }
  const id = saveInspection('pending');
  if (id) {
    sendApprovalEmail(id);
    sendToPowerAutomate(id); // SharePoint連携
  }
}

function saveInspection(status) {
  const name = document.getElementById('inspector-name').value.trim();
  if (!name) { showToast('点検者名を入力してください', 'error'); return null; }

  const checks = collectChecklistData();
  const data = getData();

  let id;
  if (editingDraftId) {
    id = editingDraftId;
    const idx = data.findIndex(d => d.id === id);
    if (idx >= 0) {
      data[idx] = {
        ...data[idx],
        vehicle: selectedVehicle,
        vehicleNumber: document.getElementById('vehicle-number').value,
        inspectorName: name,
        inspectorDept: document.getElementById('inspector-dept').value,
        inspectionDate: document.getElementById('inspection-date').value,
        location: document.getElementById('inspection-location').value,
        weather: selectedWeather,
        checks,
        overallComment: document.getElementById('overall-comment').value,
        approvalComment: document.getElementById('approval-comment').value,
        status,
        updatedAt: new Date().toISOString()
      };
    }
  } else {
    id = 'insp_' + Date.now();
    data.push({
      id,
      vehicle: selectedVehicle,
      vehicleNumber: document.getElementById('vehicle-number').value,
      inspectorName: name,
      inspectorDept: document.getElementById('inspector-dept').value,
      inspectionDate: document.getElementById('inspection-date').value,
      location: document.getElementById('inspection-location').value,
      weather: selectedWeather,
      checks,
      overallComment: document.getElementById('overall-comment').value,
      approvalComment: document.getElementById('approval-comment').value,
      status,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });
  }

  saveData(data);
  updateApprovalBadge();

  const msg = status === 'draft' ? '下書きとして保存しました' : '承認依頼の準備ができました ✉️';
  showToast(msg, 'success');
  
  setTimeout(() => { 
    if (status !== 'draft') {
      resetForm(); 
      showPage('dashboard'); 
    } else {
      resetForm();
      showPage('history');
    }
  }, 3000);
  return id;
}

// ===== フォームリセット =====
function resetForm() {
  selectedVehicle = '';
  selectedWeather = '';
  currentStep = 1;
  editingDraftId = null;
  document.querySelectorAll('.vehicle-card').forEach(c => c.classList.remove('selected'));
  document.querySelectorAll('.weather-btn').forEach(b => b.classList.remove('selected'));
  document.getElementById('inspector-name').value = '';
  document.getElementById('inspector-dept').value = '';
  document.getElementById('vehicle-number').value = '';
  document.getElementById('inspection-location').value = '';
  document.getElementById('inspection-date').value = '';
  document.getElementById('overall-comment').value = '';
  document.getElementById('approval-comment').value = '';
  document.getElementById('btn-step1-next').disabled = true;
  const h1 = document.querySelector('#page-new-inspection .page-header h1');
  if (h1) h1.textContent = '新規点検';
  goToStep(1);
}

// ===== 下書き再編集 =====
function resumeDraft(id) {
  closeModal();
  const data = getData();
  const insp = data.find(d => d.id === id);
  if (!insp) { showToast('データが見つかりません', 'error'); return; }

  editingDraftId = id;
  selectedVehicle = insp.vehicle;
  document.querySelectorAll('.vehicle-card').forEach(c => {
    c.classList.remove('selected');
    if (c.querySelector('h3') && c.querySelector('h3').textContent.trim() === insp.vehicle) {
      c.classList.add('selected');
    }
  });
  document.getElementById('btn-step1-next').disabled = false;

  document.getElementById('inspector-name').value = insp.inspectorName || '';
  document.getElementById('inspector-dept').value = insp.inspectorDept || '';
  document.getElementById('vehicle-number').value = insp.vehicleNumber || '';
  document.getElementById('inspection-location').value = insp.location || '';
  document.getElementById('inspection-date').value = insp.inspectionDate || '';
  document.getElementById('overall-comment').value = insp.overallComment || '';
  document.getElementById('approval-comment').value = insp.approvalComment || '';

  selectedWeather = insp.weather || '';
  document.querySelectorAll('.weather-btn').forEach(b => {
    b.classList.remove('selected');
    if (b.textContent.includes(insp.weather)) b.classList.add('selected');
  });

  showPage('new-inspection');
  const h1 = document.querySelector('#page-new-inspection .page-header h1');
  if (h1) h1.textContent = '📝 下書き編集';

  goToStep(2);
  setTimeout(() => {
    goToStep(3);
    if (insp.checks) {
      Object.entries(insp.checks).forEach(([itemId, checkData]) => {
        const ci = document.getElementById('ci-' + itemId);
        if (!ci) return;
        const btnClass = checkData.status;
        const btn = ci.querySelector('.check-btn.' + btnClass);
        if (btn) {
          ci.querySelectorAll('.check-btn').forEach(b => b.classList.remove('selected'));
          btn.classList.add('selected');
        }
        const commentInput = document.getElementById('comment-' + itemId);
        if (commentInput && checkData.comment) commentInput.value = checkData.comment;
        
        if (checkData.photo) {
          const photoArea = ci.querySelector('.checklist-photo-area');
          const preview = document.createElement('div');
          preview.className = 'photo-preview-container';
          preview.innerHTML = `
            <img src="${checkData.photo}" class="photo-preview" onclick="viewPhoto('${checkData.photo}')">
            <button class="btn-remove-photo" onclick="removePhoto('${itemId}')">✕</button>
          `;
          photoArea.appendChild(preview);
        }
      });
    }
    showToast('下書きを読み込みました。続きから編集できます', 'success');
  }, 100);
}

// ===== メール送信 =====
function sendApprovalEmail(inspectionId) {
  const settings = getSettings();
  const email = (settings.approverEmail || '').trim();
  if (!email) return;

  const data = getData();
  const insp = data.find(d => d.id === inspectionId);
  if (!insp) return;

  let ok=0, warn=0, ng=0;
  if (insp.checks) {
    Object.values(insp.checks).forEach(c => {
      if(c.status === 'ok') ok++; 
      else if(c.status === 'warn') warn++; 
      else if(c.status === 'ng') ng++;
    });
  }

  const subject = `【点検承認依頼】${insp.vehicle}${insp.vehicleNumber ? ' ' + insp.vehicleNumber : ''}`;
  const bodyLines = [
    `${settings.approverName || '助役'} 様`,
    '',
    `以下の点検報告の承認をお願いします。`,
    '',
    `■車両: ${insp.vehicle} ${insp.vehicleNumber || ''}`,
    `■点検者: ${insp.inspectorName || ''}`,
    `■日時: ${insp.inspectionDate ? insp.inspectionDate.replace('T',' ') : ''}`,
    '',
    `【結果】 良好:${ok} / 要注意:${warn} / 不良:${ng}`,
    `【件名】 ${insp.approvalComment || 'なし'}`,
    '',
    `点検システムより送信`
  ];

  const mailtoLink = `mailto:${email}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(bodyLines.join('\n'))}`;
  const a = document.createElement('a');
  a.href = mailtoLink;
  a.target = '_blank';
  document.body.appendChild(a);
  a.click();
  setTimeout(() => document.body.removeChild(a), 500);
  showToast(`メールアプリを起動しました。<br><small>開かない場合は設定でメルアドを確認してください</small>`, 'success');
}

function testEmailConfig() {
  const settings = getSettings();
  const email = (settings.approverEmail || '').trim();
  if (!email) { showToast('メールアドレスが設定されていません', 'error'); return; }
  const subject = "車両点検システム: テスト送信";
  const body = "このメールが表示されていれば、設定は正しいです。";
  const mailtoLink = `mailto:${email}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  window.location.href = mailtoLink;
  showToast('テストメールを起動しました', 'success');
}

// ===== Power Automate / SharePoint 連携 =====
async function sendToPowerAutomate(inspectionId) {
  const settings = getSettings();
  const url = (settings.powerAutomateUrl || '').trim();
  if (!url) return;

  const data = getData();
  const insp = data.find(d => d.id === inspectionId);
  if (!insp) return;

  const statusEl = document.getElementById('cloud-sync-status');
  const msgEl = document.getElementById('sync-msg');
  if (statusEl) {
    statusEl.style.display = 'block';
    msgEl.textContent = '同期中...';
    msgEl.style.color = 'var(--white)';
  }

  let ok=0, warn=0, ng=0;
  if (insp.checks) {
    Object.values(insp.checks).forEach(c => {
      if(c.status === 'ok') ok++; 
      else if(c.status === 'warn') warn++; 
      else if(c.status === 'ng') ng++;
    });
  }

  const payload = {
    id: insp.id,
    vehicle: insp.vehicle,
    vehicleNumber: insp.vehicleNumber || '',
    inspectorName: insp.inspectorName || '',
    inspectorDept: insp.inspectorDept || '',
    inspectionDate: insp.inspectionDate || '',
    location: insp.location || '',
    weather: insp.weather || '',
    summary: `良好:${ok}, 要注意:${warn}, 不良:${ng}`,
    overallComment: insp.overallComment || '',
    approvalComment: insp.approvalComment || '',
    status: insp.status,
    timestamp: new Date().toISOString()
  };

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (response.ok) {
      if (msgEl) {
        msgEl.textContent = '同期完了 ✅';
        msgEl.style.color = 'var(--green)';
      }
      showToast('SharePointへの同期が完了しました', 'success');
    } else {
      throw new Error('Response error: ' + response.status);
    }
  } catch (error) {
    console.error('PA Sync Error:', error);
    if (msgEl) {
      msgEl.textContent = '同期失敗 ❌';
      msgEl.style.color = 'var(--red)';
    }
    showToast('SharePoint同期に失敗しました。URLを確認してください。', 'error');
  }
}

// ===== 履歴 =====
function renderHistory() {
  const vehicleFilter = document.getElementById('filter-vehicle').value;
  const statusFilter = document.getElementById('filter-status').value;
  let data = getData();
  if (vehicleFilter) data = data.filter(d => d.vehicle === vehicleFilter);
  if (statusFilter) data = data.filter(d => d.status === statusFilter);
  data = [...data].sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt));

  const container = document.getElementById('history-list');
  if (data.length === 0) {
    container.innerHTML = `<div class="empty-state"><svg viewBox="0 0 64 64" fill="none"><circle cx="32" cy="32" r="28" stroke="#FF6B00" stroke-width="2" opacity="0.3"/></svg><p>該当する点検記録がありません</p></div>`;
    return;
  }
  container.innerHTML = data.map(d => `
    <div class="inspection-item" onclick="openInspectionDetail('${d.id}')">
      <div class="item-vehicle-icon">${getVehicleSVG(d.vehicle)}</div>
      <div class="item-info">
        <div class="item-title">${d.vehicle} ${d.vehicleNumber ? '【' + d.vehicleNumber + '】' : ''}</div>
        <div class="item-sub">点検者: ${d.inspectorName || '未記入'} ／ ${d.location || '場所未記入'} ／ ${formatDate(d.createdAt)}</div>
      </div>
      <div class="item-actions">
        <span class="status-badge ${statusClass(d.status)}">${statusLabel(d.status)}</span>
        ${d.status==='draft' ? `<button class="btn-secondary" style="padding:6px 12px;font-size:12px" onclick="event.stopPropagation();resumeDraft('${d.id}')">再編集</button>` : ''}
      </div>
    </div>`).join('');
}

function filterHistory() { renderHistory(); }

// ===== 承認管理 =====
let approvalLoggedIn = false;

function renderApprovalPage() {
  const gate = document.getElementById('approval-pin-gate');
  const content = document.getElementById('approval-content');
  if (gate) gate.style.display = approvalLoggedIn ? 'none' : 'block';
  if (content) content.style.display = approvalLoggedIn ? 'block' : 'none';
  if (approvalLoggedIn) renderApprovalList();
}

function checkApprovalPin() {
  const pin = document.getElementById('approval-pin').value;
  const settings = getSettings();
  const correctPin = settings.approvalPin || '1234';
  if (pin === correctPin) {
    approvalLoggedIn = true;
    renderApprovalPage();
  } else {
    showToast('PINコードが正しくありません', 'error');
    document.getElementById('approval-pin').value = '';
  }
}

function logoutApproval() {
  approvalLoggedIn = false;
  const pinInput = document.getElementById('approval-pin');
  if (pinInput) pinInput.value = '';
  renderApprovalPage();
}

function renderApprovalList() {
  const data = getData().filter(d => d.status === 'pending');
  const container = document.getElementById('approval-list');
  if (data.length === 0) {
    container.innerHTML = `<div class="empty-state"><svg viewBox="0 0 64 64" fill="none"><circle cx="32" cy="32" r="28" stroke="#27ae60" stroke-width="2" opacity="0.3"/><path d="M20 32 L28 40 L44 24" stroke="#27ae60" stroke-width="3" stroke-linecap="round" opacity="0.5"/></svg><p>承認待ちの点検はありません</p></div>`;
    return;
  }
  container.innerHTML = data.map(d => {
    let ok=0,warn=0,ng=0;
    if(d.checks) Object.values(d.checks).forEach(c=>{if(c.status==='ok')ok++;else if(c.status==='warn')warn++;else if(c.status==='ng')ng++;});
    return `
    <div class="approval-card">
      <div class="approval-card-header">
        <div style="width:60px;height:42px">${getVehicleSVG(d.vehicle)}</div>
        <h3>${d.vehicle} ${d.vehicleNumber ? '【' + d.vehicleNumber + '】' : ''}</h3>
        <span class="status-badge status-pending">承認待ち</span>
      </div>
      <div class="approval-card-info">
        <div><label>点検者</label><span>${d.inspectorName || '-'}</span></div>
        <div><label>点検日時</label><span>${d.inspectionDate ? d.inspectionDate.replace('T',' ') : '-'}</span></div>
        <div><label>点検場所</label><span>${d.location || '-'}</span></div>
        <div><label>良好</label><span style="color:var(--green)">${ok}件</span></div>
        <div><label>要注意</label><span style="color:var(--yellow)">${warn}件</span></div>
        <div><label>不良</label><span style="color:var(--red)">${ng}件</span></div>
      </div>
      ${d.approvalComment ? `<div style="background:rgba(255,255,255,0.04);padding:10px 14px;border-radius:8px;font-size:13px;margin-bottom:12px;color:var(--gray-400)">💬 ${d.approvalComment}</div>` : ''}
      <div style="margin-bottom:10px">
        <textarea class="reject-comment" id="reject-comment-${d.id}" placeholder="差し戻しコメント（差し戻し時に記入）" rows="2"></textarea>
      </div>
      <div class="approval-actions">
        <button class="btn-approve" onclick="approveInspection('${d.id}')">✅ 承認する</button>
        <button class="btn-reject" onclick="rejectInspection('${d.id}')">↩️ 差し戻す</button>
        <button class="btn-export-sm" onclick="openInspectionDetail('${d.id}')">📋 詳細確認</button>
        <button class="btn-export-sm" onclick="exportPDF('${d.id}')">📄 PDF出力</button>
        <button class="btn-export-sm" onclick="exportExcel('${d.id}')">📊 Excel出力</button>
      </div>
    </div>`;
  }).join('');
}

function approveInspection(id) {
  const data = getData();
  const idx = data.findIndex(d => d.id === id);
  if (idx < 0) return;
  data[idx].status = 'approved';
  data[idx].approvedAt = new Date().toISOString();
  data[idx].updatedAt = new Date().toISOString();
  saveData(data);
  updateApprovalBadge();
  showToast('承認しました ✅', 'success');
  renderApprovalList();
  sendApprovalResultEmail(id, 'approved', '');
}

function rejectInspection(id) {
  const comment = document.getElementById('reject-comment-' + id).value;
  const data = getData();
  const idx = data.findIndex(d => d.id === id);
  if (idx < 0) return;
  data[idx].status = 'rejected';
  data[idx].rejectedAt = new Date().toISOString();
  data[idx].rejectComment = comment;
  data[idx].updatedAt = new Date().toISOString();
  saveData(data);
  updateApprovalBadge();
  showToast('差し戻しました', 'error');
  renderApprovalList();
  sendApprovalResultEmail(id, 'rejected', comment);
}

function sendApprovalResultEmail(id, result, comment) {
  // 実装省略
}

// ===== 詳細モーダル =====
function openInspectionDetail(id) {
  const data = getData();
  const insp = data.find(d => d.id === id);
  if (!insp) return;

  let ok=0,warn=0,ng=0;
  if(insp.checks) Object.values(insp.checks).forEach(c=>{if(c.status==='ok')ok++;else if(c.status==='warn')warn++;else if(c.status==='ng')ng++;});

  let checklistHTML = '';
  const sections = {};
  if (insp.checks) {
    Object.values(insp.checks).forEach(c => {
      if (!sections[c.section]) sections[c.section] = [];
      sections[c.section].push(c);
    });
    Object.entries(sections).forEach(([sec, items]) => {
      const sectionPhotos = items.filter(it => it.photo).map(it => it.photo);
      checklistHTML += `
        <div class="modal-checklist-section">
          <h4>${sec}</h4>
          ${items.map(item => `
            <div class="modal-check-row">
              <span>${item.name} ${item.photo ? '📷' : ''}</span>
              <div style="display:flex;align-items:center;gap:8px">
                ${item.comment ? `<span style="font-size:11px;color:var(--gray-400)">${item.comment}</span>` : ''}
                <span class="modal-check-status ${item.status==='ok'?'status-approved':item.status==='warn'?'status-pending':item.status==='ng'?'status-rejected':'status-draft'}">
                  ${item.status==='ok'?'✅ 良好':item.status==='warn'?'⚠️ 要注意':item.status==='ng'?'❌ 不良':'－ 未'}
                </span>
              </div>
            </div>`).join('')}
          ${sectionPhotos.length > 0 ? `
            <div class="modal-photo-grid">
              ${sectionPhotos.map(p => `<div class="modal-photo-item" onclick="viewPhoto('${p}')"><img src="${p}"></div>`).join('')}
            </div>` : ''}
        </div>`;
    });
  }

  document.getElementById('modal-content').innerHTML = `
    <div class="modal-inspection-header">
      <div class="modal-vehicle-svg">${getVehicleSVG(insp.vehicle)}</div>
      <div>
        <h2 style="font-size:20px;font-weight:900">${insp.vehicle} ${insp.vehicleNumber ? '【'+insp.vehicleNumber+'】' : ''}</h2>
        <span class="status-badge ${statusClass(insp.status)}" style="margin-top:6px;display:inline-block">${statusLabel(insp.status)}</span>
      </div>
    </div>
    <div class="modal-meta-grid">
      <div class="modal-meta-item"><label>点検者</label><span>${insp.inspectorName || '-'}</span></div>
      <div class="modal-meta-item"><label>所属</label><span>${insp.inspectorDept || '-'}</span></div>
      <div class="modal-meta-item"><label>点検日時</label><span>${insp.inspectionDate ? insp.inspectionDate.replace('T',' ') : '-'}</span></div>
      <div class="modal-meta-item"><label>点検場所</label><span>${insp.location || '-'}</span></div>
      <div class="modal-meta-item"><label>天候</label><span>${insp.weather || '-'}</span></div>
      <div class="modal-meta-item"><label>良好/要注意/不良</label><span style="color:var(--green)">${ok}</span> / <span style="color:var(--yellow)">${warn}</span> / <span style="color:var(--red)">${ng}</span></div>
    </div>
    ${checklistHTML}
    ${insp.overallComment ? `<div style="background:rgba(255,255,255,0.04);padding:12px 16px;border-radius:8px;margin-bottom:16px"><p style="font-size:12px;color:var(--gray-400);margin-bottom:4px">総合所見</p><p style="font-size:14px">${insp.overallComment}</p></div>` : ''}
    ${insp.rejectComment ? `<div style="background:rgba(231,76,60,0.08);border:1px solid rgba(231,76,60,0.2);padding:12px 16px;border-radius:8px;margin-bottom:16px"><p style="font-size:12px;color:var(--red);margin-bottom:4px">差し戻しコメント</p><p style="font-size:14px">${insp.rejectComment}</p></div>` : ''}
    <div class="modal-export-actions">
      <button class="btn-primary" onclick="exportPDF('${insp.id}')">📄 PDF出力</button>
      <button class="btn-save" onclick="exportExcel('${insp.id}')">📊 Excel出力</button>
      ${insp.status === 'draft' ? `<button class="btn-secondary" onclick="resumeDraft('${insp.id}')">✏️ 続きを編集</button>` : ''}
      <button class="btn-danger" onclick="deleteInspection('${insp.id}')">🗑️ 削除</button>
    </div>`;

  document.getElementById('modal-overlay').classList.add('active');
}

function closeModal() {
  document.getElementById('modal-overlay').classList.remove('active');
}

// ===== 削除 =====
function deleteInspection(id) {
  if (!confirm('この点検記録を削除しますか？')) return;
  const data = getData().filter(d => d.id !== id);
  saveData(data);
  closeModal();
  updateApprovalBadge();
  showToast('削除しました', 'success');
  updateDashboard();
}

// ===== 設定 =====
function loadSettings() {
  const s = getSettings();
  if (s.approverEmail) document.getElementById('approver-email').value = s.approverEmail;
  if (s.approverName) document.getElementById('approver-name').value = s.approverName;
  if (s.approvalPin) document.getElementById('approval-pin-setting').value = s.approvalPin;
  if (s.powerAutomateUrl) document.getElementById('power-automate-url').value = s.powerAutomateUrl;
  
  const autoLockEl = document.getElementById('setting-auto-lock');
  if (autoLockEl) autoLockEl.value = s.autoLockMinutes || 5;

  const vn = getVehicleNumbers();
  const vm = document.getElementById('vehicle-numbers-manager');
  vm.innerHTML = VEHICLES.map(v => `
    <div class="vnumber-vehicle">
      <label>${v}</label>
      <input type="text" id="vn-${VEHICLE_IDS[v]}" value="${vn[v] || ''}" placeholder="例: K-001, K-002（カンマ区切り）">
    </div>`).join('');

  // 車両別推奨空気圧の設定描画
  const tirePressures = getTirePressures();
  const tm = document.getElementById('tire-pressure-manager');
  tm.innerHTML = VEHICLES.map(v => `
    <div class="vnumber-vehicle">
      <label>${v}</label>
      <input type="text" id="tp-${VEHICLE_IDS[v]}" value="${tirePressures[v] || ''}" placeholder="例: 350kPa, 3.5bar">
    </div>`).join('');

  renderRefPhotoSettings();
  renderCustomItemsList();
}

function saveSettings() {
  const s = getSettings();
  s.approverEmail = document.getElementById('approver-email').value;
  s.approverName = document.getElementById('approver-name').value;
  s.approvalPin = document.getElementById('approval-pin-setting').value || '1234';
  const autoLockEl = document.getElementById('setting-auto-lock');
  if (autoLockEl) s.autoLockMinutes = parseInt(autoLockEl.value) || 5;
  
  saveSettingsData(s);
  showToast('設定を保存しました ✅', 'success');
}

function savePASettings() {
  const s = getSettings();
  s.powerAutomateUrl = document.getElementById('power-automate-url').value;
  saveSettingsData(s);
  showToast('連携設定を保存しました ✅', 'success');
}

function saveVehicleNumbers() {
  const vn = {};
  VEHICLES.forEach(v => {
    const el = document.getElementById('vn-' + VEHICLE_IDS[v]);
    if (el) vn[v] = el.value;
  });
  saveVehicleNumbersData(vn);
  showToast('車両番号を保存しました ✅', 'success');
}

function exportAllData() {
  const data = getData();
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = '点検データ_' + new Date().toISOString().slice(0,10) + '.json';
  a.click();
}

function importData() { document.getElementById('import-file').click(); }

function handleImport(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const data = JSON.parse(e.target.result);
      if (Array.isArray(data)) {
        saveData(data);
        showToast(`${data.length}件のデータをインポートしました`, 'success');
        updateApprovalBadge();
      } else { showToast('無効なデータ形式です', 'error'); }
    } catch { showToast('ファイルの読み込みに失敗しました', 'error'); }
  };
  reader.readAsText(file);
  event.target.value = '';
}

function clearAllData() {
  if (!confirm('全ての点検データを削除しますか？この操作は元に戻せません。')) return;
  localStorage.removeItem('inspections');
  updateApprovalBadge();
  showToast('全データを削除しました', 'success');
}

// ===== Excel出力 =====
function exportExcel(id) {
  const data = getData();
  const insp = data.find(d => d.id === id);
  if (!insp) return;

  const rows = [
    ['車両点検表'],
    [],
    ['車両種別', insp.vehicle],
    ['車両番号', insp.vehicleNumber || ''],
    ['点検日時', insp.inspectionDate ? insp.inspectionDate.replace('T',' ') : ''],
    ['点検者', insp.inspectorName || ''],
    ['所属', insp.inspectorDept || ''],
    ['点検場所', insp.location || ''],
    ['天候', insp.weather || ''],
    ['ステータス', statusLabel(insp.status)],
    [],
    ['点検項目', '結果', 'コメント'],
  ];

  if (insp.checks) {
    let currentSection = '';
    Object.values(insp.checks).forEach(c => {
      if (c.section !== currentSection) {
        rows.push(['【' + c.section + '】', '', '']);
        currentSection = c.section;
      }
      const statusTxt = c.status === 'ok' ? '良好' : c.status === 'warn' ? '要注意' : c.status === 'ng' ? '不良' : '未確認';
      rows.push([c.name, statusTxt, c.comment || '']);
    });
  }

  rows.push([]);
  rows.push(['総合所見', insp.overallComment || '']);
  if (insp.rejectComment) rows.push(['差し戻しコメント', insp.rejectComment]);

  const wb = XLSX.utils.book_new();
  const ws = XLSX.utils.aoa_to_sheet(rows);
  ws['!cols'] = [{ wch: 30 }, { wch: 12 }, { wch: 40 }];
  XLSX.utils.book_append_sheet(wb, ws, '点検表');
  const filename = `点検_${insp.vehicle}_${insp.vehicleNumber || ''}_${(insp.inspectionDate || '').slice(0,10)}.xlsx`;
  XLSX.writeFile(wb, filename);
  showToast('Excelを出力しました 📊', 'success');
}

// ===== PDF出力 =====
async function exportPDF(id) {
  const data = getData();
  const insp = data.find(d => d.id === id);
  if (!insp) return;

  showToast('PDF生成中...', 'success');

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });

  // フォント設定（日本語はフォントが必要だが、CDN版では文字化けする場合がある）
  // 日本語PDFはcanvas経由で出力する方法を採用
  const printDiv = document.createElement('div');
  printDiv.style.cssText = 'position:fixed;top:-9999px;left:-9999px;width:780px;background:#fff;padding:32px;font-family:\'Noto Sans JP\',sans-serif;color:#000;font-size:13px;line-height:1.6;';

  let checkRows = '';
  if (insp.checks) {
    let currentSection = '';
    Object.values(insp.checks).forEach(c => {
      if (c.section !== currentSection) {
        checkRows += `<tr style="background:#1a3a5c;color:#fff"><td colspan="3" style="padding:6px 10px;font-weight:bold">【${c.section}】</td></tr>`;
        currentSection = c.section;
      }
      const statusTxt = c.status==='ok'?'✅ 良好':c.status==='warn'?'⚠️ 要注意':c.status==='ng'?'❌ 不良':'－ 未確認';
      const statusColor = c.status==='ok'?'#27ae60':c.status==='warn'?'#f39c12':c.status==='ng'?'#e74c3c':'#888';
      checkRows += `<tr style="border-bottom:1px solid #eee"><td style="padding:5px 10px">${c.name}</td><td style="padding:5px 10px;color:${statusColor};font-weight:600">${statusTxt}</td><td style="padding:5px 10px;color:#555">${c.comment||''}</td></tr>`;
    });
  }

  let ok=0,warn=0,ng=0;
  if(insp.checks) Object.values(insp.checks).forEach(c=>{if(c.status==='ok')ok++;else if(c.status==='warn')warn++;else if(c.status==='ng')ng++;});

  printDiv.innerHTML = `
    <div style="background:#0d1b2a;color:#fff;padding:20px 24px;border-radius:8px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between">
      <div>
        <h1 style="font-size:20px;font-weight:900;margin:0">車両点検表</h1>
        <p style="margin:4px 0 0;font-size:13px;opacity:0.7">Vehicle Inspection Report</p>
      </div>
      <div style="text-align:right;font-size:12px;opacity:0.7">出力日: ${new Date().toLocaleDateString('ja-JP')}</div>
    </div>
    <table style="width:100%;border-collapse:collapse;margin-bottom:16px;font-size:13px">
      <tr style="background:#f4f6f8"><td style="padding:6px 10px;width:100px;color:#666;font-weight:600">車両種別</td><td style="padding:6px 10px;font-weight:700;font-size:15px">${insp.vehicle}</td><td style="padding:6px 10px;width:100px;color:#666;font-weight:600">車両番号</td><td style="padding:6px 10px">${insp.vehicleNumber||'未記入'}</td></tr>
      <tr><td style="padding:6px 10px;color:#666;font-weight:600">点検日時</td><td style="padding:6px 10px">${insp.inspectionDate?insp.inspectionDate.replace('T',' '):'-'}</td><td style="padding:6px 10px;color:#666;font-weight:600">点検場所</td><td style="padding:6px 10px">${insp.location||'-'}</td></tr>
      <tr style="background:#f4f6f8"><td style="padding:6px 10px;color:#666;font-weight:600">点検者</td><td style="padding:6px 10px">${insp.inspectorName||'-'}</td><td style="padding:6px 10px;color:#666;font-weight:600">所属</td><td style="padding:6px 10px">${insp.inspectorDept||'-'}</td></tr>
      <tr><td style="padding:6px 10px;color:#666;font-weight:600">天候</td><td style="padding:6px 10px">${insp.weather||'-'}</td><td style="padding:6px 10px;color:#666;font-weight:600">ステータス</td><td style="padding:6px 10px;font-weight:700;color:${insp.status==='approved'?'#27ae60':insp.status==='rejected'?'#e74c3c':'#f39c12'}">${statusLabel(insp.status)}</td></tr>
    </table>
    <div style="display:flex;gap:12px;margin-bottom:16px">
      <div style="flex:1;background:#e8f8ef;border-radius:6px;padding:10px;text-align:center"><div style="font-size:22px;font-weight:900;color:#27ae60">${ok}</div><div style="font-size:11px;color:#555">良好</div></div>
      <div style="flex:1;background:#fef8e8;border-radius:6px;padding:10px;text-align:center"><div style="font-size:22px;font-weight:900;color:#f39c12">${warn}</div><div style="font-size:11px;color:#555">要注意</div></div>
      <div style="flex:1;background:#fdecea;border-radius:6px;padding:10px;text-align:center"><div style="font-size:22px;font-weight:900;color:#e74c3c">${ng}</div><div style="font-size:11px;color:#555">不良</div></div>
    </div>
    <table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px">
      <thead><tr style="background:#0d1b2a;color:#fff"><th style="padding:8px 10px;text-align:left">点検項目</th><th style="padding:8px 10px;text-align:center;width:100px">結果</th><th style="padding:8px 10px;text-align:left">コメント</th></tr></thead>
      <tbody>${checkRows}</tbody>
    </table>
    ${insp.overallComment ? `<div style="background:#f4f6f8;padding:12px;border-radius:6px;margin-bottom:12px"><strong>総合所見:</strong><br>${insp.overallComment}</div>` : ''}
    ${insp.rejectComment ? `<div style="background:#fdecea;border:1px solid #e74c3c;padding:12px;border-radius:6px"><strong style="color:#e74c3c">差し戻しコメント:</strong><br>${insp.rejectComment}</div>` : ''}
    <div style="margin-top:32px;display:flex;justify-content:space-between">
      <div style="text-align:center"><div style="border-top:1px solid #000;width:160px;padding-top:4px;font-size:11px">点検者署名</div></div>
      <div style="text-align:center"><div style="border-top:1px solid #000;width:160px;padding-top:4px;font-size:11px">助役 確認・承認</div></div>
    </div>`;

  document.body.appendChild(printDiv);

  try {
    const canvas = await html2canvas(printDiv, { scale: 2, useCORS: true, backgroundColor: '#ffffff' });
    const imgData = canvas.toDataURL('image/png');
    const imgWidth = 190;
    const imgHeight = (canvas.height * imgWidth) / canvas.width;
    let y = 10;
    const pageHeight = doc.internal.pageSize.getHeight() - 20;

    if (imgHeight <= pageHeight) {
      doc.addImage(imgData, 'PNG', 10, y, imgWidth, imgHeight);
    } else {
      // 複数ページ対応
      let remainingHeight = imgHeight;
      let sourceY = 0;
      while (remainingHeight > 0) {
        const sliceH = Math.min(pageHeight, remainingHeight);
        const sliceCanvas = document.createElement('canvas');
        sliceCanvas.width = canvas.width;
        sliceCanvas.height = (sliceH / imgWidth) * canvas.width;
        const ctx = sliceCanvas.getContext('2d');
        ctx.drawImage(canvas, 0, sourceY * (canvas.width / imgWidth), canvas.width, sliceCanvas.height, 0, 0, sliceCanvas.width, sliceCanvas.height);
        const sliceData = sliceCanvas.toDataURL('image/png');
        doc.addImage(sliceData, 'PNG', 10, y, imgWidth, sliceH);
        remainingHeight -= sliceH;
        sourceY += sliceH;
        if (remainingHeight > 0) { doc.addPage(); y = 10; }
      }
    }

    const filename = `点検_${insp.vehicle}_${insp.vehicleNumber||''}_${(insp.inspectionDate||'').slice(0,10)}.pdf`;
    doc.save(filename);
    showToast('PDFを出力しました 📄', 'success');
  } catch (e) {
    showToast('PDF生成に失敗しました: ' + e.message, 'error');
  } finally {
    document.body.removeChild(printDiv);
  }
}

// ===== ユーティリティ =====
function formatDate(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  return d.getFullYear() + '/' + (d.getMonth()+1) + '/' + d.getDate() + ' ' + String(d.getHours()).padStart(2,'0') + ':' + String(d.getMinutes()).padStart(2,'0');
}

function statusLabel(s) {
  return { draft:'下書き', pending:'承認待ち', approved:'承認済み', rejected:'差し戻し' }[s] || s;
}

function statusClass(s) {
  return { draft:'status-draft', pending:'status-pending', approved:'status-approved', rejected:'status-rejected' }[s] || '';
}

function updateApprovalBadge() {
  const count = getData().filter(d => d.status === 'pending').length;
  const badge = document.getElementById('approval-badge');
  badge.style.display = count > 0 ? 'inline-flex' : 'none';
  badge.textContent = count;
}

function showToast(msg, type = 'success') {
  const t = document.getElementById('toast');
  t.innerHTML = msg;
  t.className = 'toast show ' + type;
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.className = 'toast'; }, 3000);
}

// ===== お手本画像管理データ =====
function getRefPhotos() {
  const data = localStorage.getItem('app_reference_photos');
  return data ? JSON.parse(data) : {};
}

function saveRefPhotos(data) {
  localStorage.setItem('app_reference_photos', JSON.stringify(data));
}

function renderRefPhotoSettings() {
  const vehicle = document.getElementById('ref-vehicle-select').value;
  const container = document.getElementById('ref-photo-manager-list');
  const refPhotos = getRefPhotos();
  const vehicleRefs = refPhotos[vehicle] || {};
  const activeItemsData = getActiveItems();
  const activeItems = activeItemsData[vehicle] || null; // null means all active by default
  const customItems = getCustomItems();

  let html = '';
  CHECKLIST.forEach(section => {
    const sectionItems = [...section.items, ...customItems.filter(ci => ci.section === section.section)];
    if (sectionItems.length === 0) return;

    // セクションタイトルを表示
    html += `<div style="grid-column: 1 / -1; margin: 15px 0 5px; color: var(--orange); font-size: 13px; font-weight: 700; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 5px;">${section.section}</div>`;
    
    sectionItems.forEach(item => {
      const customImg = vehicleRefs[item.id];
      const displayImg = customImg || item.refImage || '';
      const isActive = activeItems ? activeItems.includes(item.id) : true;
      
      html += `
        <div class="ref-manager-item">
          <div class="ref-manager-preview">
            <img src="${displayImg}" id="ref-prev-${item.id}" onerror="this.outerHTML='<span>No Image</span>'">
          </div>
          <div class="ref-manager-info">
            <span class="ref-manager-name">${item.name}</span>
            <span class="ref-manager-note">${item.note}</span>
          </div>
          <div class="ref-manager-actions">
            <label class="ref-item-toggle">
              <input type="checkbox" ${isActive ? 'checked' : ''} onchange="toggleItemActive('${vehicle}', '${item.id}', this.checked)">
              表示
            </label>
            <button class="btn-secondary" style="padding:4px 10px; font-size:11px" onclick="triggerRefUpload('${vehicle}', '${item.id}')">写真変更</button>
            ${customImg ? `<button class="btn-danger" style="padding:4px 10px; font-size:11px" onclick="deleteRefPhoto('${vehicle}', '${item.id}')">初期化</button>` : ''}
          </div>
        </div>
      `;
    });
  });
  container.innerHTML = html;
}

function getActiveItems() {
  const data = localStorage.getItem('app_active_items');
  return data ? JSON.parse(data) : {};
}

function saveActiveItems(data) {
  localStorage.setItem('app_active_items', JSON.stringify(data));
}

function toggleItemActive(vehicle, itemId, checked) {
  const data = getActiveItems();
  if (!data[vehicle]) {
    // If first time setting active items for this vehicle, initialize with all except this if needed
    data[vehicle] = [];
    CHECKLIST.forEach(s => s.items.forEach(it => {
       if (it.id !== itemId || checked) data[vehicle].push(it.id);
    }));
  }
  
  if (checked) {
    if (!data[vehicle].includes(itemId)) data[vehicle].push(itemId);
  } else {
    data[vehicle] = data[vehicle].filter(id => id !== itemId);
  }
  saveActiveItems(data);
  showToast('設定を更新しました', 'success');
}

function triggerRefUpload(vehicle, itemId) {
  const input = document.getElementById('ref-photo-input');
  input.onchange = (e) => handleRefPhotoUpload(vehicle, itemId, e);
  input.click();
}

function handleRefPhotoUpload(vehicle, itemId, event) {
  const file = event.target.files[0];
  if (!file) return;

  showToast('お手本画像を処理中...', 'success');
  
  // お手本画像はさらに小さく圧縮（400px）
  const reader = new FileReader();
  reader.onload = (e) => {
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      let width = img.width;
      let height = img.height;
      const max = 400; // お手本は小さくて良い

      if (width > height) {
        if (width > max) { height *= max / width; width = max; }
      } else {
        if (height > max) { width *= max / height; height = max; }
      }

      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0, width, height);
      const base64 = canvas.toDataURL('image/jpeg', 0.5); // 品質も抑える
      
      const refPhotos = getRefPhotos();
      if (!refPhotos[vehicle]) refPhotos[vehicle] = {};
      refPhotos[vehicle][itemId] = base64;
      saveRefPhotos(refPhotos);
      
      renderRefPhotoSettings();
      showToast('お手本画像を更新しました', 'success');
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

function deleteRefPhoto(vehicle, itemId) {
  if (!confirm('この項目のお手本画像を初期状態に戻しますか？')) return;
  const refPhotos = getRefPhotos();
  if (refPhotos[vehicle] && refPhotos[vehicle][itemId]) {
    delete refPhotos[vehicle][itemId];
    saveRefPhotos(refPhotos);
    renderRefPhotoSettings();
    showToast('初期状態に戻しました', 'success');
  }
}

// ===== 空気圧管理 =====
function getTirePressures() {
  const data = localStorage.getItem('app_tire_pressures');
  return data ? JSON.parse(data) : {};
}

function saveTirePressuresData(data) {
  localStorage.setItem('app_tire_pressures', JSON.stringify(data));
}

function saveTirePressures() {
  const tp = {};
  VEHICLES.forEach(v => {
    const el = document.getElementById('tp-' + VEHICLE_IDS[v]);
    if (el) tp[v] = el.value;
  });
  saveTirePressuresData(tp);
  showToast('推奨空気圧を保存しました ✅', 'success');
}

// ===== カスタム項目管理 =====
function getCustomItems() {
  const data = localStorage.getItem('app_custom_items');
  return data ? JSON.parse(data) : [];
}

function saveCustomItemsData(data) {
  localStorage.setItem('app_custom_items', JSON.stringify(data));
}

function addCustomItem() {
  const nameEl = document.getElementById('custom-item-name');
  const noteEl = document.getElementById('custom-item-note');
  const sectionEl = document.getElementById('custom-item-section');
  
  const name = nameEl.value.trim();
  const note = noteEl.value.trim();
  const section = sectionEl.value;
  
  if (!name) {
    showToast('項目名を入力してください', 'error');
    return;
  }
  
  const customItems = getCustomItems();
  const newItem = {
    id: 'custom_' + Date.now(),
    name: name,
    note: note,
    section: section
  };
  
  customItems.push(newItem);
  saveCustomItemsData(customItems);
  
  nameEl.value = '';
  noteEl.value = '';
  
  renderCustomItemsList();
  renderRefPhotoSettings(); // 写真管理側も更新
  showToast('項目を追加しました', 'success');
}

function deleteCustomItem(id) {
  if (!confirm('この項目を完全に削除しますか？')) return;
  
  let customItems = getCustomItems();
  customItems = customItems.filter(it => it.id !== id);
  saveCustomItemsData(customItems);
  
  renderCustomItemsList();
  renderRefPhotoSettings();
  showToast('項目を削除しました', 'success');
}

function renderCustomItemsList() {
  const list = document.getElementById('custom-items-list');
  const customItems = getCustomItems();
  
  if (customItems.length === 0) {
    list.innerHTML = '<p style="font-size:12px; color:#555">追加済みの項目はありません</p>';
    return;
  }
  
  list.innerHTML = customItems.map(it => `
    <div style="display:flex; align-items:center; gap:8px; background:rgba(255,255,255,0.03); padding:8px 12px; border-radius:4px; border:1px solid rgba(255,255,255,0.05)">
      <div style="flex:1">
        <div style="font-size:12px; font-weight:700">${it.name} <span style="font-weight:400; color:#888; margin-left:6px">[${it.section}]</span></div>
        <div style="font-size:11px; color:#666">${it.note}</div>
      </div>
      <button onclick="deleteCustomItem('${it.id}')" style="background:none; border:none; color:var(--red); cursor:pointer; padding:4px">✕</button>
    </div>
  `).join('');
}

function getVehicleSVG(vehicle) {
  const svgs = {
    '電動キックボード': `<svg viewBox="0 0 80 50" fill="none" style="width:100%;height:100%"><circle cx="15" cy="38" r="8" stroke="#FF6B00" stroke-width="2.5"/><circle cx="65" cy="38" r="8" stroke="#FF6B00" stroke-width="2.5"/><rect x="14" y="12" width="3" height="26" fill="#fff" rx="1"/><rect x="8" y="10" width="15" height="4" fill="#FF6B00" rx="2"/><path d="M17 38 L55 20 L65 38" stroke="#fff" stroke-width="2.5" fill="none"/><rect x="50" y="16" width="20" height="6" fill="#FF6B00" rx="2" opacity="0.8"/></svg>`,
    '電動自転車': `<svg viewBox="0 0 80 50" fill="none" style="width:100%;height:100%"><circle cx="15" cy="35" r="11" stroke="#FF6B00" stroke-width="2.5"/><circle cx="65" cy="35" r="11" stroke="#FF6B00" stroke-width="2.5"/><circle cx="15" cy="35" r="4" fill="#FF6B00"/><circle cx="65" cy="35" r="4" fill="#FF6B00"/><path d="M15 35 L28 15 L45 15 L65 35" stroke="#fff" stroke-width="2.5" fill="none"/><path d="M28 15 L38 35" stroke="#fff" stroke-width="2"/><rect x="35" y="22" width="12" height="6" fill="#FF6B00" rx="2" opacity="0.9"/></svg>`,
    'ハマー': `<svg viewBox="0 0 80 50" fill="none" style="width:100%;height:100%"><circle cx="15" cy="35" r="11" stroke="#FF6B00" stroke-width="2.5"/><circle cx="65" cy="35" r="11" stroke="#FF6B00" stroke-width="2.5"/><circle cx="15" cy="35" r="4" fill="#FF6B00"/><circle cx="65" cy="35" r="4" fill="#FF6B00"/><path d="M15 35 L25 12 L55 12 L65 35" stroke="#fff" stroke-width="2.5" fill="none"/><path d="M25 12 L35 35" stroke="#fff" stroke-width="2"/><path d="M20 12 L60 12" stroke="#FF6B00" stroke-width="3"/><path d="M22 8 L28 8" stroke="#fff" stroke-width="4" stroke-linecap="round"/></svg>`,
    'e-bike': `<svg viewBox="0 0 80 50" fill="none" style="width:100%;height:100%"><circle cx="15" cy="35" r="11" stroke="#FF6B00" stroke-width="2.5"/><circle cx="65" cy="35" r="11" stroke="#FF6B00" stroke-width="2.5"/><circle cx="15" cy="35" r="4" fill="#FF6B00"/><circle cx="65" cy="35" r="4" fill="#FF6B00"/><path d="M15 35 L27 14 L48 14 L65 35" stroke="#fff" stroke-width="2.5" fill="none"/><path d="M27 14 L36 35" stroke="#fff" stroke-width="2"/><path d="M38 20 L50 20 L46 28 L54 28" stroke="#FF6B00" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`
  };
  return svgs[vehicle] || svgs['電動自転車'];
}

// ===== 初期化 =====
document.addEventListener('DOMContentLoaded', () => {
  showPage('dashboard');

  // ナビのアクティブ状態を画面に合わせる
  document.getElementById('nav-dashboard').classList.add('active');
});
