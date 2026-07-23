const MENU_PERMISSIONS = [
    ['menu:text-to-image','文生图'],['menu:enhance','细节增强'],['menu:image-edit','图片编辑'],['menu:angle','角度控制'],
    ['menu:online','在线生图'],['menu:gpt-chat','GPT 对话'],['menu:canvas','无限画布'],['menu:asset-manager','素材库'],
    ['menu:api-settings','API 设置'],['menu:more-settings','更多设置'],['menu:workflow-settings','工作流设置'],
    ['menu:organization-permissions','组织与权限'],
];
const CAPABILITY_PERMISSIONS = [
    ['action:read','查看内容'],['action:write','生成与修改'],['settings:api:manage','修改 API 设置'],
    ['settings:more:manage','修改更多设置'],['organization:view','查看组织架构'],
];
const state = {auth:null,departments:[],users:[],roles:[],selectedRole:'',search:''};
const elements = {
    sourceBadge:document.getElementById('sourceBadge'),identityLabel:document.getElementById('identityLabel'),notice:document.getElementById('notice'),
    refreshBtn:document.getElementById('refreshBtn'),memberSearch:document.getElementById('memberSearch'),memberSummary:document.getElementById('memberSummary'),
    memberRows:document.getElementById('memberRows'),memberEmpty:document.getElementById('memberEmpty'),roleList:document.getElementById('roleList'),
    newRoleBtn:document.getElementById('newRoleBtn'),roleName:document.getElementById('roleName'),roleDisplayName:document.getElementById('roleDisplayName'),
    saveRoleBtn:document.getElementById('saveRoleBtn'),permissionGroups:document.getElementById('permissionGroups'),toast:document.getElementById('toast'),
};

function escapeHtml(value){return String(value??'').replace(/[&<>'"]/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));}
function canManage(){return Boolean(state.auth?.user?.is_super_admin&&state.auth?.config?.bitable_enabled);}
async function api(url,options={}){
    const response=await fetch(url,{...options,cache:'no-store',headers:{'Content-Type':'application/json',...(options.headers||{})}});
    const payload=await response.json().catch(()=>({}));
    if(!response.ok)throw new Error(payload.detail||`请求失败（${response.status}）`);
    return payload;
}
let toastTimer=0;
function showToast(message,error=false){clearTimeout(toastTimer);elements.toast.textContent=message;elements.toast.classList.toggle('error',error);elements.toast.hidden=false;toastTimer=setTimeout(()=>{elements.toast.hidden=true;},2600);}
function showNotice(message,error=false){elements.notice.textContent=message||'';elements.notice.classList.toggle('error',error);elements.notice.hidden=!message;}
function departmentMap(){const map=new Map();state.departments.forEach(item=>{const id=String(item.open_department_id||item.department_id||'');if(id)map.set(id,item.name||id);});return map;}
function roleOptions(selected){return state.roles.map(role=>`<option value="${escapeHtml(role.name)}" ${role.name===selected?'selected':''}>${escapeHtml(role.display_name||role.name)}</option>`).join('');}
function renderMembers(){
    const departments=departmentMap();const query=state.search.trim().toLowerCase();
    const users=state.users.filter(user=>{if(!query)return true;const names=(user.department_ids||[]).map(id=>departments.get(String(id))||id).join(' ');return [user.name,user.email,user.mobile,names].join(' ').toLowerCase().includes(query);});
    elements.memberSummary.textContent=`${users.length} / ${state.users.length} 名成员`;elements.memberEmpty.hidden=users.length>0;
    elements.memberRows.innerHTML=users.map(user=>{const id=user.open_id||user.user_id||'';const names=(user.department_ids||[]).map(item=>departments.get(String(item))||item).filter(Boolean).join('、')||'未分配部门';const locked=Boolean(user.is_super_admin);const disabled=canManage()&&!locked?'':'disabled';const displayName=`${user.name||'未命名成员'}${locked?'（默认超管）':''}`;const action=user.managed&&!locked&&canManage()?'<button class="remove-command" type="button" data-action="remove">移除授权</button>':`<span class="assignment-state">${user.managed?'已授权':'默认成员'}</span>`;return `<tr data-user-id="${escapeHtml(id)}"><td><div class="member-name">${escapeHtml(displayName)}</div><div class="member-sub">${escapeHtml(user.email||user.mobile||id)}</div></td><td><div class="department-list">${escapeHtml(names)}</div></td><td><select data-field="role" ${disabled}>${roleOptions(user.role)}</select></td><td><select data-field="status" ${disabled}><option value="active" ${user.status!=='disabled'?'selected':''}>启用</option><option value="disabled" ${user.status==='disabled'?'selected':''}>停用</option></select></td><td>${action}</td></tr>`;}).join('');
}
function renderRoleList(){elements.roleList.innerHTML=state.roles.map(role=>`<button class="role-item ${role.name===state.selectedRole?'active':''}" type="button" data-role="${escapeHtml(role.name)}"><span>${escapeHtml(role.display_name||role.name)}</span><span class="role-key">${escapeHtml(role.name)}</span></button>`).join('');}
function selectedRole(){return state.roles.find(role=>role.name===state.selectedRole)||null;}
function permissionGroup(title,items,selected){return `<section class="permission-group"><h2>${escapeHtml(title)}</h2><div class="permission-options">${items.map(([key,label])=>`<label class="permission-option"><input type="checkbox" value="${escapeHtml(key)}" ${selected.has(key)?'checked':''} ${canManage()?'':'disabled'}><span>${escapeHtml(label)}</span></label>`).join('')}</div></section>`;}
function renderRoleEditor(){const role=selectedRole();const selected=new Set(role?.permissions||[]);elements.roleName.value=role?.name||'';elements.roleDisplayName.value=role?.display_name||'';elements.roleName.disabled=!canManage()||Boolean(role);elements.roleDisplayName.disabled=!canManage();elements.saveRoleBtn.disabled=!canManage();elements.newRoleBtn.disabled=!canManage();elements.permissionGroups.innerHTML=permissionGroup('菜单',MENU_PERMISSIONS,selected)+permissionGroup('操作能力',CAPABILITY_PERMISSIONS,selected);}
function renderAll(){renderMembers();renderRoleList();renderRoleEditor();}

async function loadData(refresh=false){
    elements.refreshBtn.disabled=true;showNotice('');
    try{
        state.auth=await api('/api/auth/me');const data=await api(`/api/admin/organization${refresh?'?refresh=true':''}`);
        state.departments=data.departments||[];state.users=data.users||[];state.roles=data.roles||[];
        if(!state.selectedRole||!state.roles.some(role=>role.name===state.selectedRole))state.selectedRole=state.roles[0]?.name||'';
        elements.identityLabel.textContent=`${state.auth.user.name||'当前用户'} · ${state.auth.user.role}`;
        elements.sourceBadge.textContent=data.source==='bitable'?'飞书多维表格':'默认权限';elements.sourceBadge.className=`status-badge ${data.source==='bitable'?'live':'warn'}`;
        if(!state.auth.config.bitable_enabled)showNotice('尚未配置飞书多维表格，当前仅可查看默认角色。');
        else if(!state.auth.user.is_super_admin)showNotice('当前账号可查看组织架构，只有超管可以修改成员和角色。');
        renderAll();
    }catch(error){showNotice(error.message||String(error),true);}finally{elements.refreshBtn.disabled=false;}
}
async function saveMember(row){
    const id=row.dataset.userId;const user=state.users.find(item=>(item.open_id||item.user_id)===id);if(!user)return;
    const role=row.querySelector('[data-field="role"]').value;const status=row.querySelector('[data-field="status"]').value;
    try{await api(`/api/admin/members/${encodeURIComponent(id)}`,{method:'PUT',body:JSON.stringify({...user,role,status})});user.role=role;user.status=status;user.managed=true;renderMembers();showToast('成员授权已保存');}
    catch(error){renderMembers();showToast(error.message||String(error),true);}
}
async function removeMember(row){
    const id=row.dataset.userId;const user=state.users.find(item=>(item.open_id||item.user_id)===id);if(!user)return;
    if(!window.confirm(`移除 ${user.name||'该成员'} 的单独授权？移除后将恢复为默认成员。`))return;
    try{await api(`/api/admin/members/${encodeURIComponent(id)}`,{method:'DELETE'});user.role='member';user.status='active';user.managed=false;renderMembers();showToast('成员已恢复为默认权限');}
    catch(error){showToast(error.message||String(error),true);}
}
async function saveRole(){
    const name=elements.roleName.value.trim().toLowerCase();const displayName=elements.roleDisplayName.value.trim();if(!name||!displayName)return showToast('请填写角色标识和名称',true);
    const permissions=Array.from(elements.permissionGroups.querySelectorAll('input[type="checkbox"]:checked')).map(input=>input.value);
    try{await api(`/api/admin/roles/${encodeURIComponent(name)}`,{method:'PUT',body:JSON.stringify({display_name:displayName,permissions})});state.selectedRole=name;await loadData(true);showToast('角色权限已保存');}
    catch(error){showToast(error.message||String(error),true);}
}
document.querySelectorAll('.tab').forEach(tab=>tab.addEventListener('click',()=>{document.querySelectorAll('.tab').forEach(item=>item.classList.toggle('active',item===tab));document.querySelectorAll('.panel').forEach(panel=>panel.classList.toggle('active',panel.id===`${tab.dataset.tab}Panel`));}));
elements.memberSearch.addEventListener('input',event=>{state.search=event.target.value;renderMembers();});elements.refreshBtn.addEventListener('click',()=>loadData(true));
elements.memberRows.addEventListener('change',event=>{const row=event.target.closest('tr[data-user-id]');if(row&&event.target.matches('select[data-field]'))saveMember(row);});
elements.memberRows.addEventListener('click',event=>{const button=event.target.closest('[data-action="remove"]');const row=button?.closest('tr[data-user-id]');if(row)removeMember(row);});
elements.roleList.addEventListener('click',event=>{const item=event.target.closest('[data-role]');if(!item)return;state.selectedRole=item.dataset.role;renderRoleList();renderRoleEditor();});
elements.newRoleBtn.addEventListener('click',()=>{state.selectedRole='';renderRoleList();renderRoleEditor();elements.roleName.focus();});elements.saveRoleBtn.addEventListener('click',saveRole);
window.addEventListener('message',event=>{if(event.origin&&event.origin!==location.origin)return;if(event.data?.type==='studio-theme')document.body.classList.toggle('theme-dark',event.data.theme==='dark');});
loadData();
