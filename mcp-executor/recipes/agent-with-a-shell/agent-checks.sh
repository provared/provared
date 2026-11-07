#!/bin/sh
# agent-checks.sh: runs inside the agent container (sh /work/agent-checks.sh). Read-only; prints no secret values. Lines starting CHK are read by run.sh.
P=UPSTREAM-TOKEN"-"
echo "--- whoami / hostname"; id -u; hostname
echo "--- environment variable names (values not shown)"; env | cut -d= -f1 | sort | tr '\n' ' '; echo
# The token's text was never given to this container, so we search for its known prefix.
echo "--- search all files for the token prefix (skipping /proc /sys /dev /node_modules which is the SDK)"
N=$(grep -rIl --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev --exclude-dir=node_modules "$P" / 2>/dev/null | wc -l)
echo "CHK file-hits=$N"
N=$(grep -rIl "$P" /node_modules 2>/dev/null | wc -l); echo "CHK sdk-hits=$N"
echo "--- search env for it"; echo "CHK env-hits=$(env | grep -c "$P")"
echo "--- search /proc/*/environ"; echo "CHK proc-hits=$(cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -c "$P")"
echo "--- what the client received"; echo "CHK received-hits=$(grep -c "$P" /tmp/received.txt)"
echo "--- mounts"; grep -E ' /work | /node_modules ' /proc/mounts | cut -d' ' -f2,4 | cut -c1-60
echo "--- reach provared-example-tools-server"
node -e "
const dns=require('dns'),net=require('net');
dns.lookup('provared-example-tools-server',(e,a)=>{console.log('CHK tools-dns='+(e?e.code:'RESOLVED '+a));
 const s=net.connect({host:'provared-example-tools-server',port:9000,timeout:4000});
 s.on('connect',()=>{console.log('CHK tools-connect=CONNECTED');s.destroy()});
 s.on('error',e=>console.log('CHK tools-connect='+e.code));
 s.on('timeout',()=>{console.log('CHK tools-connect=TIMEOUT');s.destroy()});});
"
echo "--- reach guard plain port 8796 (guard listens on 127.0.0.1 inside its own container)"
node -e "
const dns=require('dns'),net=require('net');
dns.lookup('provared-example-guard',(e,a)=>{console.log('provared-example-guard resolves to',a);
 for (const p of [8796,9000]) {
  const s=net.connect({host:a,port:p,timeout:4000});
  s.on('connect',()=>{console.log('CHK port'+p+'=CONNECTED');s.destroy()});
  s.on('error',e=>console.log('CHK port'+p+'='+e.code));
  s.on('timeout',()=>{console.log('CHK port'+p+'=TIMEOUT');s.destroy()});}
});
"
echo "--- a request with a foreign Origin, and one with a wrong secret (status codes only)"
node --input-type=module -e "
const body=JSON.stringify({jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-06-18',capabilities:{},clientInfo:{name:'probe',version:'1'}}});
const go=async(label,h)=>{try{const r=await fetch('https://provared-example-guard:8443/mcp',{method:'POST',headers:{'content-type':'application/json',accept:'application/json, text/event-stream',...h},body});console.log('CHK '+label+'='+r.status);await r.arrayBuffer();}catch(e){console.log('CHK '+label+'=ERROR '+(e.cause&&e.cause.code||e.message));}};
const ok={authorization:'Bearer '+process.env.AGENT_SECRET};
await go('origin-evil',{...ok,origin:'https://evil.example'});
await go('wrong-secret',{authorization:'Bearer not-the-secret'});
"
