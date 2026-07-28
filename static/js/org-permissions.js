const MENU_PERMISSION_GROUPS = [
    {title:'本地功能',note:'暂未启用',items:[['menu:text-to-image','文生图'],['menu:enhance','细节增强'],['menu:image-edit','图片编辑'],['menu:angle','角度控制']]},
    {title:'在线功能',items:[['menu:online','在线生图'],['menu:gpt-chat','GPT 对话']]},
    {title:'创作与资源',items:[['menu:canvas','无限画布'],['menu:asset-manager','素材库']]},
    {title:'系统设置',items:[['menu:api-settings','API 设置'],['menu:more-settings','更多设置'],['menu:workflow-settings','工作流设置'],['menu:organization-permissions','组织与权限']]},
];
const CAPABILITY_PERMISSIONS = [
    ['action:read','查看内容'],['action:write','生成与修改'],['settings:api:manage','修改 API 设置'],
    ['settings:more:manage','修改更多设置'],['organization:view','查看组织架构'],
];
const PLATFORM_ONLY_PERMISSIONS = new Set(['menu:api-settings','menu:more-settings','menu:workflow-settings','settings:api:manage','settings:more:manage']);
const state = {auth:null,departments:[],users:[],roles:[],tenants:[],selectedRole:'',selectedTenant:'',search:''};
const elements = {
    sourceBadge:document.getElementById('sourceBadge'),identityLabel:document.getElementById('identityLabel'),notice:document.getElementById('notice'),
    refreshBtn:document.getElementById('refreshBtn'),memberSearch:document.getElementById('memberSearch'),memberSummary:document.getElementById('memberSummary'),
    memberRows:document.getElementById('memberRows'),memberEmpty:document.getElementById('memberEmpty'),roleList:document.getElementById('roleList'),
    newRoleBtn:document.getElementById('newRoleBtn'),roleName:document.getElementById('roleName'),roleDisplayName:document.getElementById('roleDisplayName'),
    saveRoleBtn:document.getElementById('saveRoleBtn'),deleteRoleBtn:document.getElementById('deleteRoleBtn'),roleScopeNote:document.getElementById('roleScopeNote'),permissionGroups:document.getElementById('permissionGroups'),toast:document.getElementById('toast'),
    tenantManagement:document.getElementById('tenantManagement'),tenantList:document.getElementById('tenantList'),selectedTenantName:document.getElementById('selectedTenantName'),selectedTenantMeta:document.getElementById('selectedTenantMeta'),tenantLoginAddress:document.getElementById('tenantLoginAddress'),tenantLoginUrl:document.getElementById('tenantLoginUrl'),copyTenantLoginBtn:document.getElementById('copyTenantLoginBtn'),newTenantBtn:document.getElementById('newTenantBtn'),syncTenantBtn:document.getElementById('syncTenantBtn'),deleteTenantBtn:document.getElementById('deleteTenantBtn'),inviteDialog:document.getElementById('inviteDialog'),inviteTenantName:document.getElementById('inviteTenantName'),inviteExpires:document.getElementById('inviteExpires'),generateInviteBtn:document.getElementById('generateInviteBtn'),inviteResult:document.getElementById('inviteResult'),inviteUrl:document.getElementById('inviteUrl'),copyInviteBtn:document.getElementById('copyInviteBtn'),inviteExpiry:document.getElementById('inviteExpiry'),
};

function escapeHtml(value){return String(value??'').replace(/[&<>'"]/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));}
function scopedUrl(path){return state.selectedTenant?`${path}${path.includes('?')?'&':'?'}tenant_key=${encodeURIComponent(state.selectedTenant)}`:path;}
function canManage(){return Boolean(state.auth?.user?.is_super_admin||state.auth?.user?.is_tenant_admin);}
async function api(url,options={}){
    const response=await fetch(url,{...options,cache:'no-store',headers:{'Content-Type':'application/json',...(options.headers||{})}});
    const payload=await response.json().catch(()=>({}));
    if(!response.ok){
        const detail=String(payload.detail||`请求失败（${response.status}）`);
        if(/bitable\/v1|多维表格/i.test(detail))throw new Error('服务端仍在运行旧权限模块，请重启服务后再试。');
        throw new Error(detail);
    }
    return payload;
}
let toastTimer=0;
function showToast(message,error=false){clearTimeout(toastTimer);elements.toast.textContent=message;elements.toast.classList.toggle('error',error);elements.toast.hidden=false;toastTimer=setTimeout(()=>{elements.toast.hidden=true;},2600);}
function showNotice(message,error=false){elements.notice.textContent=message||'';elements.notice.classList.toggle('error',error);elements.notice.hidden=!message;}
function departmentMap(){const map=new Map();state.departments.forEach(item=>{const id=String(item.open_department_id||item.department_id||'');if(id)map.set(id,item.name||id);});return map;}
function roleOptions(selected){return state.roles.map(role=>`<option value="${escapeHtml(role.name)}" ${role.name===selected?'selected':''}>${escapeHtml(role.display_name||role.name)}</option>`).join('');}
function renderTenantManagement(){if(!elements.tenantManagement)return;const visible=Boolean(state.auth?.user?.is_super_admin);elements.tenantManagement.hidden=!visible;if(!visible)return;const tenant=state.tenants.find(item=>item.tenant_key===state.selectedTenant);elements.tenantList.innerHTML=state.tenants.map(item=>`<button class="tenant-list-item ${item.tenant_key===state.selectedTenant?'active':''}" type="button" data-tenant="${escapeHtml(item.tenant_key)}"><span><strong>${escapeHtml(item.name||'未命名企业')}</strong><small>${item.credential_configured?'已完成飞书认证':'待完成飞书认证'}</small></span><i class="tenant-auth-state ${item.credential_configured?'verified':'pending'}">${item.credential_configured?'已认证':'待认证'}</i></button>`).join('');elements.selectedTenantName.textContent=tenant?.name||'请选择企业';elements.selectedTenantMeta.textContent=tenant?`${tenant.credential_configured?'已完成飞书认证':'待完成飞书认证'} · ${state.users.length} 名成员`:'';const loginPath=tenant?.slug?`/t/${encodeURIComponent(tenant.slug)}/login`:'';const loginUrl=loginPath?`${location.origin}${loginPath}`:'';elements.tenantLoginUrl.textContent=loginUrl;elements.tenantLoginAddress.hidden=!loginUrl;elements.deleteTenantBtn.disabled=!tenant||state.tenants.length<=1;elements.syncTenantBtn.disabled=!tenant||!tenant.credential_configured;}
function renderMembers(){
    const departments=departmentMap();const query=state.search.trim().toLowerCase();
    const users=state.users.filter(user=>{if(!query)return true;const names=(user.department_ids||[]).map(id=>departments.get(String(id))||id).join(' ');return [user.name,user.email,user.mobile,names].join(' ').toLowerCase().includes(query);});
    elements.memberSummary.textContent=`${users.length} / ${state.users.length} 名成员`;elements.memberEmpty.hidden=users.length>0;
    elements.memberRows.innerHTML=users.map(user=>{const id=user.open_id||user.user_id||'';const names=(user.department_ids||[]).map(item=>departments.get(String(item))||item).filter(Boolean).join('、')||'未分配部门';const locked=Boolean(user.is_super_admin);const isGuest=user.role==='guest';const disabled=canManage()&&!locked?'':'disabled';const adminDisabled=state.auth?.user?.is_super_admin&&!locked&&!isGuest?'':'disabled';const adminTitle=isGuest?'访客不能设为企业管理员':'企业管理员';const displayName=`${user.name||'未命名成员'}${locked?'（平台超管）':''}`;const action=user.managed&&!locked&&canManage()?'<button class="remove-command" type="button" data-action="remove" title="移除单独角色覆盖，恢复默认 member 权限">恢复默认</button>':`<span class="assignment-state" title="该成员使用默认 member 权限">${user.managed?'已授权':'默认成员'}</span>`;return `<tr data-user-id="${escapeHtml(id)}"><td><div class="member-name">${escapeHtml(displayName)}</div><div class="member-sub">${escapeHtml(user.email||user.mobile||id)}</div></td><td><div class="department-list">${escapeHtml(names)}</div></td><td><select data-field="role" ${disabled}>${roleOptions(user.role)}</select></td><td><input type="checkbox" data-field="tenantAdmin" ${user.is_tenant_admin?'checked':''} ${adminDisabled} title="${adminTitle}" aria-label="${adminTitle}"></td><td><select data-field="status" ${disabled}><option value="active" ${user.status!=='disabled'?'selected':''}>启用</option><option value="disabled" ${user.status==='disabled'?'selected':''}>停用</option></select></td><td>${action}</td></tr>`;}).join('');
}
function renderRoleList(){elements.roleList.innerHTML=state.roles.map(role=>`<button class="role-item ${role.name===state.selectedRole?'active':''}" type="button" data-role="${escapeHtml(role.name)}"><span>${escapeHtml(role.display_name||role.name)}</span><span class="role-key">${escapeHtml(role.name)}</span></button>`).join('');}
function selectedRole(){return state.roles.find(role=>role.name===state.selectedRole)||null;}
function permissionOptions(items,selected){return items.map(([key,label])=>{const disabled=!canManage()||(!state.auth?.user?.is_super_admin&&PLATFORM_ONLY_PERMISSIONS.has(key));return `<label class="permission-option"><input type="checkbox" value="${escapeHtml(key)}" ${selected.has(key)?'checked':''} ${disabled?'disabled':''}><span>${escapeHtml(label)}</span></label>`;}).join('');}
function menuPermissionGroups(selected){return `<section class="permission-group permission-menu"><h2>菜单权限</h2><div class="menu-permission-grid">${MENU_PERMISSION_GROUPS.map(group=>`<section class="menu-permission-section"><div class="menu-permission-heading"><strong>${escapeHtml(group.title)}</strong>${group.note?`<span>${escapeHtml(group.note)}</span>`:''}</div><div class="permission-options">${permissionOptions(group.items,selected)}</div></section>`).join('')}</div></section>`;}
function permissionGroup(title,items,selected){return `<section class="permission-group permission-capabilities"><h2>${escapeHtml(title)}</h2><div class="permission-options">${permissionOptions(items,selected)}</div></section>`;}
function renderRoleEditor(){const role=selectedRole();const selected=new Set(role?.permissions||[]);elements.roleName.value=role?.name||'';elements.roleDisplayName.value=role?.display_name||'';elements.roleName.disabled=!canManage()||Boolean(role);elements.roleDisplayName.disabled=!canManage();elements.saveRoleBtn.disabled=!canManage();elements.newRoleBtn.disabled=!canManage();if(elements.deleteRoleBtn)elements.deleteRoleBtn.disabled=!canManage()||!role||Boolean(role.system);if(elements.roleScopeNote){const isSuperAdmin=Boolean(state.auth?.user?.is_super_admin);elements.roleScopeNote.textContent=isSuperAdmin?'当前为平台超管：平台超管始终拥有全部权限；角色修改只影响被分配该角色的企业成员。':'角色权限只对被分配该角色的企业成员生效。';elements.roleScopeNote.hidden=!role;}elements.permissionGroups.innerHTML=menuPermissionGroups(selected)+permissionGroup('操作能力',CAPABILITY_PERMISSIONS,selected);}
function renderAll(){renderTenantManagement();renderMembers();renderRoleList();renderRoleEditor();}

async function loadData(refresh=false){
    elements.refreshBtn.disabled=true;showNotice('');
    try{
        state.auth=await api('/api/auth/me');
        if(state.auth.user.is_super_admin){const tenantData=await api('/api/admin/tenants');state.tenants=tenantData.tenants||[];const sessionTenant=state.auth.user.tenant_key;const sessionTenantIsAvailable=state.tenants.some(item=>item.tenant_key===sessionTenant);if(!state.selectedTenant||!state.tenants.some(item=>item.tenant_key===state.selectedTenant))state.selectedTenant=sessionTenantIsAvailable?sessionTenant:(state.tenants[0]?.tenant_key||'');}
        else state.selectedTenant=state.auth.user.tenant_key||'default';
        const tenantQuery=state.selectedTenant?`tenant_key=${encodeURIComponent(state.selectedTenant)}`:'';const data=await api(`/api/admin/organization?${tenantQuery}${tenantQuery&&refresh?'&':''}${refresh?'refresh=true&_='+Date.now():''}`);
        state.departments=data.departments||[];state.users=data.users||[];state.roles=data.roles||[];
        if(!state.selectedRole||!state.roles.some(role=>role.name===state.selectedRole))state.selectedRole=state.roles[0]?.name||'';
        const currentIdentity=new Set([state.auth.user.open_id,state.auth.user.user_id,state.auth.user.union_id].filter(Boolean));
        const currentDirectoryUser=state.users.find(item=>[item.open_id,item.user_id,item.union_id].filter(Boolean).some(value=>currentIdentity.has(value)));
        const directoryDepartments=(currentDirectoryUser?.department_ids||[]).map(item=>departmentMap().get(String(item))||item).filter(Boolean);
        const departmentNames=state.auth.user.department_names?.length?state.auth.user.department_names:directoryDepartments;
        state.auth.user.department_names=departmentNames;
        const identityRole=state.auth.user.is_super_admin?'ADMIN':(state.auth.user.is_tenant_admin?'企业管理员':state.auth.user.role);
        elements.identityLabel.textContent=[state.auth.user.name||'当前用户',departmentNames.join('、')||'未分配部门',identityRole].filter(Boolean).join(' · ');
        const rawTenantName=String(data.tenant?.name||state.auth.tenant?.name||'').trim();const tenantKey=String(data.tenant?.tenant_key||data.tenant_key||'').trim();const tenantName=rawTenantName&&rawTenantName!==tenantKey&&!/^[a-f0-9]{12,}$/i.test(rawTenantName)?rawTenantName:(tenantKey==='default'?'默认企业':'当前企业');
        elements.sourceBadge.textContent=`${tenantName} · 本地权限`;elements.sourceBadge.className='status-badge live';
        if(state.auth.config?.permission_store!=='local')showNotice('服务端仍在运行旧权限模块，请重启服务后再试。',true);
        else if(!canManage())showNotice('当前账号仅可查看组织架构，成员和角色由企业管理员维护。');
        renderAll();
    }catch(error){showNotice(error.message||String(error),true);}finally{elements.refreshBtn.disabled=false;}
}
async function saveMember(row){
    const id=row.dataset.userId;const user=state.users.find(item=>(item.open_id||item.user_id)===id);if(!user)return;
    if(row.dataset.saving==='true')return;row.dataset.saving='true';row.querySelectorAll('select,input,button').forEach(control=>{control.disabled=true;});
    const role=row.querySelector('[data-field="role"]').value;const status=row.querySelector('[data-field="status"]').value;const is_tenant_admin=Boolean(row.querySelector('[data-field="tenantAdmin"]')?.checked);
    try{const saved=await api(scopedUrl(`/api/admin/members/${encodeURIComponent(id)}`),{method:'PUT',body:JSON.stringify({...user,role,status,is_tenant_admin})});user.role=saved.role||role;user.status=saved.status||status;user.is_tenant_admin=Boolean(saved.is_tenant_admin);user.managed=Boolean(user.role!=='member'||user.status!=='active'||user.is_tenant_admin);renderMembers();showToast('成员授权已保存');}
    catch(error){renderMembers();showToast(error.message||String(error),true);}finally{delete row.dataset.saving;}
}
async function removeMember(row){
    const id=row.dataset.userId;const user=state.users.find(item=>(item.open_id||item.user_id)===id);if(!user)return;
    if(!window.confirm(`将 ${user.name||'该成员'} 恢复为默认 member 权限？这不会删除通讯录成员，也不会阻止登录。`))return;
    try{await api(scopedUrl(`/api/admin/members/${encodeURIComponent(id)}`),{method:'DELETE'});user.role='member';user.status='active';user.managed=false;renderMembers();showToast('成员已恢复为默认权限');}
    catch(error){showToast(error.message||String(error),true);}
}
async function saveRole(){
    const name=elements.roleName.value.trim().toLowerCase();const displayName=elements.roleDisplayName.value.trim();if(!name||!displayName)return showToast('请填写角色标识和名称',true);
    const permissions=Array.from(elements.permissionGroups.querySelectorAll('input[type="checkbox"]:checked')).map(input=>input.value);
    elements.saveRoleBtn.disabled=true;
    try{await api(scopedUrl(`/api/admin/roles/${encodeURIComponent(name)}`),{method:'PUT',body:JSON.stringify({display_name:displayName,permissions})});state.selectedRole=name;await loadData(true);showToast('角色权限已保存');}
    catch(error){showToast(error.message||String(error),true);}finally{elements.saveRoleBtn.disabled=!canManage();}
}
async function deleteRole(){
    const role=selectedRole();if(!role||role.system||!canManage())return;
    if(!window.confirm(`删除角色“${role.display_name||role.name}”？`))return;
    try{await api(scopedUrl(`/api/admin/roles/${encodeURIComponent(role.name)}`),{method:'DELETE'});state.selectedRole='';await loadData(true);showToast('角色已删除');}
    catch(error){showToast(error.message||String(error),true);}
}
async function generateInvite(){elements.generateInviteBtn.disabled=true;try{const result=await api('/api/admin/tenant-invitations',{method:'POST',body:JSON.stringify({tenant_name:elements.inviteTenantName.value.trim(),expires_in_minutes:Number(elements.inviteExpires.value)||60})});elements.inviteUrl.value=result.invite_url;elements.inviteExpiry.textContent=`有效期至 ${new Date(result.expires_at).toLocaleString()}`;elements.inviteResult.hidden=false;}catch(error){showToast(error.message||String(error),true);}finally{elements.generateInviteBtn.disabled=false;}}
async function syncTenant(){const key=state.selectedTenant;if(!key)return;elements.syncTenantBtn.disabled=true;try{const result=await api(`/api/admin/tenants/${encodeURIComponent(key)}/sync`,{method:'POST'});showToast(`已同步 ${result.members} 名成员、${result.departments} 个部门`);await loadData(true);}catch(error){showToast(error.message||String(error),true);}finally{elements.syncTenantBtn.disabled=false;}}
async function deleteTenant(){const key=state.selectedTenant;const tenant=state.tenants.find(item=>item.tenant_key===key);if(!key||!tenant||state.tenants.length<=1)return;if(!window.confirm(`解除企业“${tenant.name||key}”？该企业的成员和角色授权也会被删除。`))return;elements.deleteTenantBtn.disabled=true;try{await api(`/api/admin/tenants/${encodeURIComponent(key)}`,{method:'DELETE'});state.selectedTenant='';showToast('企业已解除');await loadData(true);}catch(error){showToast(error.message||String(error),true);}finally{elements.deleteTenantBtn.disabled=false;}}
document.querySelectorAll('.tab').forEach(tab=>tab.addEventListener('click',()=>{document.querySelectorAll('.tab').forEach(item=>item.classList.toggle('active',item===tab));document.querySelectorAll('.panel').forEach(panel=>panel.classList.toggle('active',panel.id===`${tab.dataset.tab}Panel`));}));
elements.memberSearch.addEventListener('input',event=>{state.search=event.target.value;renderMembers();});elements.refreshBtn.addEventListener('click',()=>loadData(true));
elements.memberRows.addEventListener('change',event=>{const row=event.target.closest('tr[data-user-id]');if(!row||!event.target.matches('select[data-field],input[data-field]'))return;if(event.target.matches('[data-field="role"]')&&event.target.value==='guest'){const tenantAdmin=row.querySelector('[data-field="tenantAdmin"]');if(tenantAdmin)tenantAdmin.checked=false;}saveMember(row);});
elements.memberRows.addEventListener('click',event=>{const button=event.target.closest('[data-action="remove"]');const row=button?.closest('tr[data-user-id]');if(row)removeMember(row);});
elements.roleList.addEventListener('click',event=>{const item=event.target.closest('[data-role]');if(!item)return;state.selectedRole=item.dataset.role;renderRoleList();renderRoleEditor();});
elements.newRoleBtn.addEventListener('click',()=>{state.selectedRole='';renderRoleList();renderRoleEditor();elements.roleName.focus();});elements.saveRoleBtn.addEventListener('click',saveRole);
elements.deleteRoleBtn?.addEventListener('click',deleteRole);
elements.tenantList?.addEventListener('click',event=>{const item=event.target.closest('[data-tenant]');if(!item)return;state.selectedTenant=item.dataset.tenant;state.selectedRole='';loadData(true);});
elements.newTenantBtn?.addEventListener('click',()=>{elements.inviteTenantName.value='';elements.inviteResult.hidden=true;elements.inviteDialog.showModal();});
elements.generateInviteBtn?.addEventListener('click',generateInvite);elements.copyInviteBtn?.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(elements.inviteUrl.value);showToast('邀请链接已复制');}catch(error){elements.inviteUrl.select();document.execCommand('copy');showToast('邀请链接已复制');}});elements.copyTenantLoginBtn?.addEventListener('click',async()=>{const value=elements.tenantLoginUrl.textContent;if(!value)return;try{await navigator.clipboard.writeText(value);showToast('企业登录地址已复制');}catch(error){const range=document.createRange();range.selectNodeContents(elements.tenantLoginUrl);const selection=window.getSelection();selection.removeAllRanges();selection.addRange(range);document.execCommand('copy');selection.removeAllRanges();showToast('企业登录地址已复制');}});elements.syncTenantBtn?.addEventListener('click',syncTenant);elements.deleteTenantBtn?.addEventListener('click',deleteTenant);
window.addEventListener('message',event=>{if(event.origin&&event.origin!==location.origin)return;if(event.data?.type==='studio-theme')document.body.classList.toggle('theme-dark',event.data.theme==='dark');});
loadData();
