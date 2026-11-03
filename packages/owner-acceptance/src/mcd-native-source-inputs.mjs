/** Full source binding for native diagnostic qualification, not a deployment claim. */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {lstat,readdir,readFile,realpath} from 'node:fs/promises';
import {resolve,relative,isAbsolute,sep,extname} from 'node:path';
import {selectMcdSourceInputs} from './mcp-diagnostics-source-inputs.mjs';

const ROOTS=['packages/owner-identity','packages/owner-web','packages/owner-acceptance',
  'infrastructure/owner-identity','tools','openspec/changes/mcp-call-diagnostics',
  'tests/bdd/changes/mcp-call-diagnostics','tests/bdd/adapters','tests/bdd/mappers','tests/bdd/conftest.py',
  'tests/bdd/features/mcp_call_diagnostics.feature','package.json','pnpm-lock.yaml','pnpm-workspace.yaml'];
const SKIP=new Set(['node_modules','dist','.next','.local','.git','__pycache__']);
const EXTENSIONS=new Set(['.ts','.tsx','.js','.mjs','.cjs','.json','.md','.yaml','.yml','.ps1','.py','.feature']);

export async function collectNativeMcdSourceInputs(repoRoot) {
  const root=resolve(repoRoot);assert.equal((await realpath(root)).toLowerCase(),root.toLowerCase());
  const files=new Map();
  async function visit(file) {
    const rel=relative(root,file);assert(rel&&!isAbsolute(rel)&&rel!=='..'&&!rel.startsWith('..'+sep));
    const info=await lstat(file);assert(!info.isSymbolicLink(),'source inventory cannot follow symbolic links');
    if(info.isDirectory()) {
      for(const entry of (await readdir(file,{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name,'en'))) {
        if(!SKIP.has(entry.name))await visit(resolve(file,entry.name));
      }
    } else if(info.isFile()&&EXTENSIONS.has(extname(file))) {
      assert.equal(info.nlink,1,'source inventory cannot bind hard-linked input');
      assert(info.size<=16*1024*1024,'source file exceeds the bounded inventory reader');
      const path=rel.split(sep).join('/');files.set(path,{path,sha256:createHash('sha256').update(await readFile(file)).digest('hex')});
    }
  }
  for(const path of ROOTS)await visit(resolve(root,path));
  return Object.fromEntries(selectMcdSourceInputs([...files.values()].sort((a,b)=>a.path.localeCompare(b.path,'en'))).map(row=>[row.path,row.sha256]));
}
