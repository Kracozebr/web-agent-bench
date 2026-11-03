import assert from 'node:assert/strict';
import test from 'node:test';
import {validateNativeObserverTarget} from './mcd-native-observer.mjs';

test('native observation is limited to the explicitly selected Google database and observer role',()=>{
  const database='oid_google_local_'+'a'.repeat(32),url='postgres://oid_observer:synthetic@postgres/'+database;
  assert.equal(validateNativeObserverTarget(url,database),database);
  for(const bad of [url.replace('oid_observer','oid_owner'),url.replace('@postgres/','@localhost/'),
    url.replace(database,'owner_identity'),url+'?options=-c%20role=oid_owner',url+'#fragment']) {
    assert.throws(()=>validateNativeObserverTarget(bad,database));
  }
  assert.throws(()=>validateNativeObserverTarget(url,'oid_acceptance_'+'a'.repeat(32)));
  assert.throws(()=>validateNativeObserverTarget(url,'oid_google_local_'+'b'.repeat(32)));
});
