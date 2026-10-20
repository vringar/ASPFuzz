# Aggregate per-command reply statuses of a structured_session run: python3 session_reply_stats.py amd_sp/runs/<run>
import glob,collections,sys
d=sys.argv[1]
c=collections.Counter()
for f in glob.glob(d+'/logs/replies_*.txt'):
    for l in open(f):
        p,cmd,s,n=l.split(); c[(int(p,16),int(cmd,16),int(s,16))]+=int(n)
tot=collections.Counter(); first=collections.defaultdict(collections.Counter); after=collections.defaultdict(collections.Counter)
nm={0xffffffff:'noreply',0xfffffffe:'TIMEOUT'}
for (p,cmd,s),n in c.items():
    st=nm.get(s,hex(s)); tot[(cmd,st)]+=n
    (first if p==0xffff else after)[(cmd)][st]+=n
print("per command (all positions): status:count")
for cmd in sorted({k[0] for k in tot}):
    print(hex(cmd), {st:n for (c2,st),n in tot.items() if c2==cmd})
print("\nmessages at position>0 (after another msg), by prev->cmd:")
rows=collections.defaultdict(collections.Counter)
for (p,cmd,s),n in c.items():
    if p!=0xffff: rows[(p,cmd)][nm.get(s,hex(s))]+=n
for k in sorted(rows, key=lambda k:-sum(rows[k].values()))[:40]:
    print(hex(k[0]),'->',hex(k[1]),dict(rows[k]))
