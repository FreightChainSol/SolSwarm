import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { PIN,SOURCE_REVISION,NATIVE_DEPENDENCIES,overlayManifest,overlayLock,withoutPackage,validateExtras,nativeIdentity,routingModule } from '../native/grok-review/build.mjs';
import { overlaySource,LOGIN_MANAGER,AUTH_MODULE,ROUTING } from '../native/grok-review/overlays.mjs';

test('Grok pin distinguishes the public snapshot from installed CLI provenance and never admits itself',()=>{
  const pin=JSON.parse(fs.readFileSync(new URL('../native/grok-review/source-pin.json',import.meta.url)));
  assert.equal(pin.commit,PIN);
  assert.equal(pin.sourceRevision,SOURCE_REVISION);
  assert.equal(pin.installedVersionIsNotSourceProvenance,true);
  assert.equal(pin.authMode,'cached_oidc_only');
  assert.equal(pin.admission,false);
});
test('Grok workspace and lock overlays preserve every upstream dependency block',()=>{
  const manifest='# Auto-generated workspace root. Prefer editing per-crate Cargo.toml files.\n[workspace]\nmembers = [\n "existing",\n]\n';
  assert.match(overlayManifest(manifest),/"freightchain-review"/);
  assert.throws(()=>overlayManifest(overlayManifest(manifest)));
  const lock=NATIVE_DEPENDENCIES.map((name)=>`[[package]]\nname = "${name}"\nversion = "${name==='sha2'?'0.10.9':'1.0.0'}"\nsource = "registry+https://invalid.test/index"\nchecksum = "fixture"\n`).join('\n');
  const result=overlayLock(lock);
  assert.equal(withoutPackage(result).trimEnd(),lock.trimEnd());
  assert.throws(()=>overlayLock(result));
  assert.throws(()=>overlayLock('missing dependency blocks'));
});
test('Grok derived source admits only declared files, not arbitrary build/config inputs',()=>{
  validateExtras(['freightchain-review/src/lib.rs',AUTH_MODULE]);
  for(const name of ['.cargo/config.toml','freightchain-review/build.rs','crates/codegen/xai-grok-login/src/foreign.rs']){
    assert.throws(()=>validateExtras([name]),/grok_untracked_source_input/);
  }
});
test('Grok native patch anchors fail closed and routing facade has no caller-controlled arguments',()=>{
  assert.throws(()=>overlaySource(LOGIN_MANAGER,'changed upstream source'),/grok_overlay_anchor_changed/);
  assert.throws(()=>overlaySource('unapproved.rs','source'),/grok_overlay_path_rejected/);
  const facade=overlaySource(ROUTING,'// fixture upstream\n');
  assert.match(facade,/freightchain_text_review_headers\(\)/);
  assert.match(facade,/CLI_CHAT_PROXY_BASE_URL_DEFAULT/);
  assert.ok(!facade.includes('Bearer '));
});
test('Grok package and recipe identities are stable and distinct bounded hashes',()=>{
  const identity=nativeIdentity();
  assert.match(identity.packageDigest,/^[a-f0-9]{64}$/);
  assert.match(identity.recipeDigest,/^[a-f0-9]{64}$/);
  assert.notEqual(identity.packageDigest,identity.recipeDigest);
  assert.deepEqual(nativeIdentity(),identity);
});
test('Grok routing projection requires the pinned function shape and excludes the full agent shell dependency',()=>{
  assert.throws(()=>routingModule('changed upstream'),/grok_native_routing_shape_changed/);
  const source='pub(crate) fn inject_url_derived_headers() { crate::util::fixture(); crate::http::fixture(); }\nfn resolve_hidden_default_web_search_sampling_config() {}';
  const projected=routingModule(source);
  assert.match(projected,/xai_grok_shell_base::util::fixture/);
  assert.match(projected,/xai_grok_http::fixture/);
  assert.match(projected,/CLI_CHAT_PROXY_BASE_URL_DEFAULT/);
  assert.ok(!NATIVE_DEPENDENCIES.includes('xai-grok-shell'));
});
