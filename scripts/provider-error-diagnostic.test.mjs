import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import {DIAGNOSTIC_CATEGORIES,DIAGNOSTIC_PARAMETERS,providerDiagnostic} from './provider-error-diagnostic.mjs';

test('diagnostic enums exactly match the native classifier contract',()=>{
  const source=fs.readFileSync(new URL('../native/grok-review/overlays/error_classifier.rs',import.meta.url),'utf8');
  for(const [name,expected]of [['CATEGORIES',DIAGNOSTIC_CATEGORIES],['PARAMETERS',DIAGNOSTIC_PARAMETERS]]){
    const match=source.match(new RegExp(`pub const ${name}: &\\[&str\\] = &\\[([\\s\\S]*?)\\];`));
    assert.ok(match);
    assert.deepEqual([...match[1].matchAll(/"([^"]+)"/g)].map((item)=>item[1]),expected);
  }
});
test('diagnostics reject extra fields, noncanonical names and invalid category/parameter pairs',()=>{
  assert.deepEqual(providerDiagnostic({category:'invalid_parameter',parameter:'tools'}),{category:'invalid_parameter',parameter:'tools'});
  for(const value of [null,[],{category:'invalid_parameter',parameter:null},
    {category:'unclassified',parameter:'tools'},
    {category:'unclassified',parameter:null,message:'dummy-private-value'},
    {category:'unclassified\u001b',parameter:null},
    {category:'invalid_parameter',parameter:'dummy-private-value'}]){
    assert.equal(providerDiagnostic(value),undefined);
  }
});
