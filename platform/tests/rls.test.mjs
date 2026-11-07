import { PGlite } from '@electric-sql/pglite';
import fs from 'node:fs';
const dir = new URL('../supabase/migrations/', import.meta.url);
// 0002 needs Supabase's storage schema, so it is not run here.
const mig = fs.readdirSync(dir).filter(f => f.endsWith('.sql') && !f.includes('storage')).sort()
  .map(f => fs.readFileSync(new URL(f, dir), 'utf8')).join('\n');
const db = new PGlite();
await db.exec(`
  create role anon nologin; create role authenticated nologin; create role service_role nologin bypassrls;
  create schema auth; create table auth.users (id uuid primary key);
  create function auth.uid() returns uuid language sql stable as
    $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
  grant usage on schema public, auth to anon, authenticated, service_role;
  grant execute on function auth.uid() to anon, authenticated;
  alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
  alter default privileges in schema public grant all on functions to anon, authenticated, service_role;
`);
await db.exec(mig);
await db.exec(`grant all on all tables in schema public to service_role;`);

const A = '00000000-0000-0000-0000-00000000000a', B = '00000000-0000-0000-0000-00000000000b', ADM = '00000000-0000-0000-0000-0000000000ad';
await db.exec(`insert into auth.users values ('${A}'),('${B}'),('${ADM}'); insert into public.admins values ('${ADM}');`);

let pass = 0, fail = 0;
async function as(role, uid, sql) {
  await db.exec(`reset role; select set_config('request.jwt.claim.sub', '${uid || ''}', false); set role ${role};`);
  try { const r = await db.query(sql); await db.exec('reset role'); return { ok: true, rows: r.rows, n: r.affectedRows }; }
  catch (e) { await db.exec('reset role'); return { ok: false, err: e.message }; }
}
function check(name, cond, extra) { if (cond) { pass++; console.log('PASS', name); } else { fail++; console.log('FAIL', name, extra ?? ''); } }
const sha = 'a'.repeat(64);

// profiles and terms
check('anon cannot create a developer profile', !(await as('anon', '', `insert into developers(id,display_name,contact_email) values ('${A}','Alice','a@x.io')`)).ok);
check('dev A creates own profile', (await as('authenticated', A, `insert into developers(id,display_name,contact_email) values ('${A}','Alice','a@x.io')`)).ok);
check('dev A cannot create profile for B', !(await as('authenticated', A, `insert into developers(id,display_name,contact_email) values ('${B}','Bob','b@x.io')`)).ok);
check('dev B creates own profile', (await as('authenticated', B, `insert into developers(id,display_name,contact_email) values ('${B}','Bob','b@x.io')`)).ok);
check('pending dev cannot create an app', !(await as('authenticated', A, `insert into apps(developer_id,slug,name,summary) values ('${A}','alpha','Alpha','An app')`)).ok);
check('dev cannot self-activate via update', !(await as('authenticated', A, `update developers set status='active' where id='${A}'`)).ok);
check('accept_terms activates dev A', (await as('authenticated', A, `select accept_terms('2026-11')`)).ok);
check('dev A is active', (await as('authenticated', A, `select status from developers where id='${A}'`)).rows?.[0]?.status === 'active');
check('dev B cannot read dev A profile', (await as('authenticated', B, `select * from developers where id='${A}'`)).rows?.length === 0);

// apps
check('dev A creates a draft app', (await as('authenticated', A, `insert into apps(developer_id,slug,name,summary) values ('${A}','alpha','Alpha','An app')`)).ok);
const appId = (await as('authenticated', A, `select id from apps where slug='alpha'`)).rows[0].id;
check('dev cannot create app for someone else', !(await as('authenticated', A, `insert into apps(developer_id,slug,name,summary) values ('${B}','beta','Beta','x')`)).ok);
check('dev cannot publish by direct update', !(await as('authenticated', A, `update apps set status='published' where id='${appId}'`)).ok);
check('dev can edit app name', (await as('authenticated', A, `update apps set name='Alpha 2' where id='${appId}'`)).ok);
check('paid price is rejected', !(await as('service_role', '', `update apps set price_cents=500 where id='${appId}'`)).ok);
check('anon cannot see draft app', (await as('anon', '', `select * from apps`)).rows.length === 0);
check('dev B cannot see A draft', (await as('authenticated', B, `select * from apps`)).rows.length === 0);

// releases and files
check('dev B cannot add release to A app', !(await as('authenticated', B, `insert into releases(app_id,version) values ('${appId}','1.0')`)).ok);
check('dev A adds a release', (await as('authenticated', A, `insert into releases(app_id,version) values ('${appId}','1.0')`)).ok);
const relId = (await as('authenticated', A, `select id from releases where version='1.0'`)).rows[0].id;
check('release starts as uploaded', (await as('authenticated', A, `select status from releases where id='${relId}'`)).rows[0].status === 'uploaded');
const addFile = (uid, name, kind, path, hash = sha, rel = relId) => as('authenticated', uid, `insert into release_files(release_id,kind,file_name,storage_path,size_bytes,sha256) values ('${rel}','${kind}','${name}','${path}',100,'${hash}')`);
check('dev B cannot add file to A release', !(await addFile(B, 'a.exe', 'executable', `${B}/a.exe`)).ok);
check('dev A cannot use another folder path', !(await addFile(A, 'a.exe', 'executable', `${B}/a.exe`)).ok);
check('bad checksum rejected', !(await addFile(A, 'a.exe', 'executable', `${A}/a.exe`, 'zzz')).ok);
check('.dll rejected as executable', !(await addFile(A, 'lib.dll', 'executable', `${A}/lib.dll`)).ok);
check('.msi rejected as executable', !(await addFile(A, 'setup.msi', 'executable', `${A}/setup.msi`)).ok);
check('.docx rejected as document', !(await addFile(A, 'guide.docx', 'document', `${A}/guide.docx`)).ok);
check('.zip rejected as document', !(await addFile(A, 'extra.zip', 'document', `${A}/extra.zip`)).ok);
check('.exe cannot be filed as a document', !(await addFile(A, 'tool.exe', 'document', `${A}/tool.exe`)).ok);
check('path tricks in file name rejected', !(await addFile(A, '..evil.exe', 'executable', `${A}/x.exe`)).ok);
check('release cannot enter review with no executable', !(await as('service_role', '', `update releases set status='in_review' where id='${relId}'`)).ok);
check('dev A uploads the .exe', (await addFile(A, 'Alpha.exe', 'executable', `${A}/alpha/Alpha.exe`)).ok);
check('dev A uploads a PDF manual', (await addFile(A, 'Manual.pdf', 'document', `${A}/alpha/Manual.pdf`)).ok);
check('dev A uploads a license text', (await addFile(A, 'LICENSE.txt', 'document', `${A}/alpha/LICENSE.txt`)).ok);
check('duplicate file name rejected', !(await addFile(A, 'Alpha.exe', 'executable', `${A}/alpha/Alpha2.exe`)).ok);
check('files are read-only for developers', !(await as('authenticated', A, `update release_files set sha256='${'b'.repeat(64)}' where file_name='Alpha.exe'`)).ok);
check('files are read-only even for the server', !(await as('service_role', '', `update release_files set sha256='${'b'.repeat(64)}' where file_name='Alpha.exe'`)).ok);
check('dev B cannot see A files', (await as('authenticated', B, `select * from release_files`)).rows.length === 0);
check('dev A can remove a mistaken upload', (await as('authenticated', A, `delete from release_files where file_name='LICENSE.txt'`)).n === 1);
check('dev A re-adds the license text', (await addFile(A, 'LICENSE.txt', 'document', `${A}/alpha/LICENSE.txt`)).ok);
check('dev cannot mark own release approved', !(await as('authenticated', A, `update releases set status='approved' where id='${relId}'`)).ok);
check('dev cannot forge a scan result', !(await as('authenticated', A, `insert into scans(release_id,engine,verdict) values ('${relId}','x','clean')`)).ok);
check('submit blocked before scan passes', !(await as('authenticated', A, `select submit_app_for_review('${appId}')`)).ok);

// 20-file cap per release
await as('authenticated', A, `insert into releases(app_id,version) values ('${appId}','cap')`);
const capId = (await as('authenticated', A, `select id from releases where version='cap'`)).rows[0].id;
let capOk = 0;
for (let i = 1; i <= 20; i++) if ((await addFile(A, `f${i}.txt`, 'document', `${A}/cap/f${i}.txt`, sha, capId)).ok) capOk++;
check('20 files fit in one release', capOk === 20);
check('21st file is refused', !(await addFile(A, 'f21.txt', 'document', `${A}/cap/f21.txt`, sha, capId)).ok);

// server-side scan (service_role)
check('server records a clean scan', (await as('service_role', '', `insert into scans(release_id,engine,verdict,detections) values ('${relId}','virustotal','clean',0)`)).ok);
check('server moves release to in_review', (await as('service_role', '', `update releases set status='in_review' where id='${relId}'`)).ok);
check('dev cannot delete files once in review', (await as('authenticated', A, `delete from release_files where file_name='Manual.pdf'`)).n === 0);
check('dev cannot add files once in review', !(await addFile(A, 'More.pdf', 'document', `${A}/alpha/More.pdf`)).ok);
check('dev A can read own scan', (await as('authenticated', A, `select * from scans`)).rows.length === 1);
check('dev B cannot read A scans', (await as('authenticated', B, `select * from scans`)).rows.length === 0);
check('submit works after scan passes', (await as('authenticated', A, `select submit_app_for_review('${appId}')`)).ok);

// admin review
check('non-admin cannot approve', !(await as('authenticated', A, `select admin_review_release('${relId}', true, 'ok')`)).ok);
check('anon cannot approve', !(await as('anon', '', `select admin_review_release('${relId}', true, 'ok')`)).ok);
check('admin approves', (await as('authenticated', ADM, `select admin_review_release('${relId}', true, 'looks good')`)).ok);
check('app is now published', (await as('anon', '', `select status from apps`)).rows[0]?.status === 'published');
const pub = await as('anon', '', `select * from published_releases`);
check('public sees approved release', pub.rows.length === 1);
check('public release shows total size', Number(pub.rows[0]?.total_size_bytes) === 300);
const pf = await as('anon', '', `select * from published_release_files order by file_name`);
check('public sees the 3 files with checksums', pf.rows.length === 3 && pf.rows.every(r => r.sha256 && r.kind));
check('public file list hides storage paths', pf.rows[0] && !('storage_path' in pf.rows[0]));
check('anon cannot read release_files table', !(await as('anon', '', `select * from release_files`)).ok);
check('anon cannot read releases table', !(await as('anon', '', `select * from releases`)).ok);
check('dev cannot delete published app', (await as('authenticated', A, `delete from apps where id='${appId}'`)).n === 0);

// downloads and reports
check('anon logs a download', (await as('anon', '', `select log_download('${relId}')`)).ok);
check('download counted', Number((await as('anon', '', `select downloads from app_download_counts`)).rows[0]?.downloads) === 1);
check('anon cannot read download_events', !(await as('anon', '', `select * from download_events`)).ok);
check('anon files a report', (await as('anon', '', `insert into reports(app_id,category,details) values ('${appId}','malware','flagged by my antivirus')`)).ok);
check('anon cannot read reports', !(await as('anon', '', `select * from reports`)).ok);
check('dev A cannot read reports', (await as('authenticated', A, `select * from reports`)).rows.length === 0);
check('admin reads reports', (await as('authenticated', ADM, `select * from reports`)).rows.length === 1);

// strikes
check('non-admin cannot add strike', !(await as('authenticated', B, `select admin_add_strike('${A}','x')`)).ok);
check('first strike keeps dev active', (await as('authenticated', ADM, `select admin_add_strike('${A}','mislabeled listing')`)).ok &&
  (await as('authenticated', A, `select status from developers where id='${A}'`)).rows[0].status === 'active');
await as('authenticated', ADM, `select admin_add_strike('${A}','second issue')`);
check('second strike suspends dev', (await as('authenticated', A, `select status from developers where id='${A}'`)).rows[0].status === 'suspended');
check('second strike delists apps', (await as('anon', '', `select * from apps`)).rows.length === 0);
check('suspended dev cannot add apps', !(await as('authenticated', A, `insert into apps(developer_id,slug,name,summary) values ('${A}','gamma','Gamma','x')`)).ok);

// ---------------------------------------------------------------- automation
const C = '00000000-0000-0000-0000-00000000000c';
await db.exec(`insert into auth.users values ('${C}')`);
await as('authenticated', C, `insert into developers(id,display_name,contact_email) values ('${C}','Cara','c@x.io')`);
await as('authenticated', C, `select accept_terms('2026-11')`);
await as('authenticated', C, `insert into apps(developer_id,slug,name,summary) values ('${C}','delta','Delta','Auto app')`);
const dApp = (await as('authenticated', C, `select id from apps where slug='delta'`)).rows[0].id;
// a release with an executable, ready for a scan decision
async function newRelease(version) {
  await as('authenticated', C, `insert into releases(app_id,version) values ('${dApp}','${version}')`);
  const id = (await as('authenticated', C, `select id from releases where version='${version}' and app_id='${dApp}'`)).rows[0].id;
  await addFile(C, 'Delta.exe', 'executable', `${C}/delta/${version}/Delta.exe`, sha, id);
  return id;
}
const decide = (rel, outcome, rate = 0) => as('service_role', '', `select record_scan_decision('${rel}','${outcome}',20,'test ${outcome}',${rate}) as d`);
const relStatus = async (rel) => (await as('service_role', '', `select status, review_flag, hold_until from releases where id='${rel}'`)).rows[0];

const r1 = await newRelease('1.0');
check('new developer starts at trust level 0', (await as('authenticated', C, `select trust_level from developers where id='${C}'`)).rows[0].trust_level === 0);
check('browser users cannot call the decision function', !(await as('authenticated', C, `select record_scan_decision('${r1}','green',1,'x')`)).ok);
check('anon cannot call the decision function', !(await as('anon', '', `select record_scan_decision('${r1}','green',1,'x')`)).ok);
check('bad outcome is refused', !(await decide(r1, 'purple')).ok);
check('green + new developer is held', (await decide(r1, 'green')).rows?.[0]?.d === 'held');
let st = await relStatus(r1);
check('held release waits in review with a hold flag', st.status === 'in_review' && st.review_flag === 'hold' && st.hold_until);
check('decision cannot be repeated', !(await decide(r1, 'green')).ok);
check('admin cannot approve before hold ends', !(await as('authenticated', ADM, `select admin_review_release('${r1}', true, 'early')`)).ok);
await as('service_role', '', `update releases set hold_until = now() - interval '1 minute' where id='${r1}'`);
check('admin approves after hold ends', (await as('authenticated', ADM, `select admin_review_release('${r1}', true, 'ok')`)).ok);
check('app published by approval', (await as('anon', '', `select slug from apps where slug='delta'`)).rows.length === 1);
check('still trust 0 after one approval', (await as('authenticated', C, `select trust_level from developers where id='${C}'`)).rows[0].trust_level === 0);

const r2 = await newRelease('1.1');
await decide(r2, 'green');
await as('service_role', '', `update releases set hold_until = now() - interval '1 minute' where id='${r2}'`);
await as('authenticated', ADM, `select admin_review_release('${r2}', true, 'ok again')`);
check('two clean approvals promote to trust 1', (await as('authenticated', C, `select trust_level from developers where id='${C}'`)).rows[0].trust_level === 1);

const r3 = await newRelease('1.2');
check('trusted developer green auto-approves', (await decide(r3, 'green')).rows?.[0]?.d === 'auto_approved');
st = await relStatus(r3);
check('auto-approved release is approved', st.status === 'approved');
check('auto-approved release is public', (await as('anon', '', `select count(*)::int as n from published_releases where id='${r3}'`)).rows[0].n === 1);

const r4 = await newRelease('1.3');
check('random spot check sends green to a human', (await decide(r4, 'green', 1)).rows?.[0]?.d === 'spot_check');
check('spot check keeps release out of the public view', (await as('anon', '', `select count(*)::int as n from published_releases where id='${r4}'`)).rows[0].n === 0);

const r5 = await newRelease('1.4');
check('yellow goes to the human queue', (await decide(r5, 'yellow')).rows?.[0]?.d === 'needs_human');
check('yellow release flagged for attention', (await relStatus(r5)).review_flag === 'attention');

const r6 = await newRelease('1.5');
check('red is rejected automatically', (await decide(r6, 'red')).rows?.[0]?.d === 'auto_rejected');
check('rejected release is not public', (await relStatus(r6)).status === 'rejected');
check('red records a strike for the developer', (await as('authenticated', C, `select count(*)::int as n from strikes where developer_id='${C}'`)).rows[0].n === 1);

check('developer can read their decision log', (await as('authenticated', C, `select count(*)::int as n from release_decisions`)).rows[0].n >= 6);
check('other developers cannot read it', (await as('authenticated', B, `select count(*)::int as n from release_decisions`)).rows[0].n === 0);
check('decision log cannot be edited', !(await as('service_role', '', `update release_decisions set reason='changed'`)).ok);
check('developer cannot write decisions', !(await as('authenticated', C, `insert into release_decisions(release_id,decision,reason) values ('${r3}','auto_approved','x')`)).ok);
check('developer cannot raise own trust', !(await as('authenticated', C, `update developers set trust_level=2 where id='${C}'`)).ok);
check('non-admin cannot set trust', !(await as('authenticated', C, `select admin_set_trust('${C}', 2::smallint)`)).ok);
check('admin can set trust', (await as('authenticated', ADM, `select admin_set_trust('${C}', 2::smallint)`)).ok);

// submit after an auto-approval publishes the draft app straight away
await as('authenticated', C, `insert into apps(developer_id,slug,name,summary) values ('${C}','echo','Echo','Second app')`);
const eApp = (await as('authenticated', C, `select id from apps where slug='echo'`)).rows[0].id;
await as('authenticated', C, `insert into releases(app_id,version) values ('${eApp}','1.0')`);
const eRel = (await as('authenticated', C, `select id from releases where app_id='${eApp}'`)).rows[0].id;
await addFile(C, 'Echo.exe', 'executable', `${C}/echo/Echo.exe`, sha, eRel);
check('trusted dev release auto-approves while app is still a draft', (await decide(eRel, 'green')).rows?.[0]?.d === 'auto_approved');
check('draft app stays hidden until the developer submits', (await as('anon', '', `select count(*)::int as n from apps where slug='echo'`)).rows[0].n === 0);
check('submit then publishes it', (await as('authenticated', C, `select submit_app_for_review('${eApp}')`)).ok &&
  (await as('anon', '', `select count(*)::int as n from apps where slug='echo'`)).rows[0].n === 1);

// scan stages written by the pipeline (migration 0004 allows 'skipped')
check('server can record a skipped stage', (await as('service_role', '', `insert into scans(release_id,engine,stage,verdict,score,report) values ('${eRel}','sandbox','sandbox','skipped',0,'{"skipped":true}')`)).ok);
check('unknown verdicts are still refused', !(await as('service_role', '', `insert into scans(release_id,engine,stage,verdict) values ('${eRel}','x','sandbox','bogus')`)).ok);
check('unknown stages are refused', !(await as('service_role', '', `insert into scans(release_id,engine,stage,verdict) values ('${eRel}','x','nonsense','clean')`)).ok);
check('server can clear a release\'s scans before a re-run', (await as('service_role', '', `delete from scans where release_id='${eRel}'`)).ok);

// public catalog view and release cleanup (migration 0005)
const cat = await as('anon', '', `select * from published_apps order by slug`);
check('catalog lists published apps with the developer name', cat.rows.some(r => r.slug === 'echo' && r.developer_name === 'Cara'));
check('catalog hides unpublished apps', !cat.rows.some(r => r.slug === 'gamma'));
check('catalog does not expose developer ids or emails', cat.rows[0] && !('developer_id' in cat.rows[0]) && !('contact_email' in cat.rows[0]));
check('catalog hides apps of suspended developers', !cat.rows.some(r => r.slug === 'alpha'));
await as('authenticated', C, `insert into releases(app_id,version) values ('${dApp}','9.9')`);
const junk = (await as('authenticated', C, `select id from releases where version='9.9'`)).rows[0].id;
await addFile(C, 'Junk.exe', 'executable', `${C}/junk/Junk.exe`, sha, junk);
check('another developer cannot delete my release', (await as('authenticated', B, `delete from releases where id='${junk}'`)).n === 0);
check('developer can delete their unscanned release', (await as('authenticated', C, `delete from releases where id='${junk}'`)).n === 1);
check('its files went with it', (await as('service_role', '', `select count(*)::int as n from release_files where release_id='${junk}'`)).rows[0].n === 0);
check('version number can be reused after deleting', (await as('authenticated', C, `insert into releases(app_id,version) values ('${dApp}','9.9')`)).ok);
check('developer cannot delete an approved release', (await as('authenticated', C, `delete from releases where id='${r3}'`)).n === 0);
check('developer cannot delete a release in review', (await as('authenticated', C, `delete from releases where id='${r4}'`)).n === 0);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
