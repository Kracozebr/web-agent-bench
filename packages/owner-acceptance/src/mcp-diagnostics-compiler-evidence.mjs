/** Keep compiler locations/codes, never diagnostic messages or source excerpts. */
export function mcdCompilerLocations(text){
  const found=[],seen=new Set();
  for(const match of String(text).slice(0,65536).matchAll(/^([A-Za-z0-9_./\\:-]{1,300})\((\d{1,7}),(\d{1,7})\):\s+error\s+(TS\d{3,6}):/gm)){
    let file=match[1].replaceAll('\\','/');
    const packageIndex=file.indexOf('packages/');
    if(packageIndex>=0)file=file.slice(packageIndex);
    if(!file.startsWith('packages/')&&!file.startsWith('src/'))file='source_path_omitted';
    const row={file,line:Number(match[2]),column:Number(match[3]),code:match[4]},key=JSON.stringify(row);
    if(!seen.has(key)){seen.add(key);found.push(row);}if(found.length>=64)break;
  }
  return found;
}
