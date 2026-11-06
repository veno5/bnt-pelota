#!/usr/bin/env python3
"""Restaurar íconos BNT Pelota desde un despliegue inmutable antiguo de Cloudflare."""
import hashlib, json, os, pathlib, sys, urllib.error, urllib.request

PROJECT="bnt-pelota"
ACCOUNT_ID="193486693c9ba649c47c57b9e550408f"
EXPECTED={
"icon-192.png":"80659d4346bbc3df2c34046a7ee6ca4be3e9451f72c854856b52451d24a2e732",
"icon-512.png":"430bfe88aecdd14d78c25aaa610646169d843e6bea93ba59845f002e6fc058f8",
"apple-touch-icon.png":"5d2634c0abdafc2cb5eed0f6bba3d7c9e08df49892890b8e1e02730e8a3bdbd1",
"favicon-64.png":"33fcfbd043d910d72abc0c96f2b111f081ad318dae2fc7d941975b692d0c1c7b",
}
PUBLIC=pathlib.Path("public")

def get_bytes(url,headers=None):
    req=urllib.request.Request(url,headers=headers or {"User-Agent":"bnt-pelota-icon-recovery/1.0"})
    with urllib.request.urlopen(req,timeout=20) as response: return response.read()

def matches(path,sha):
    return path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest()==sha

def recover():
    if all(matches(PUBLIC/name,sha) for name,sha in EXPECTED.items()):
        print("Ícono original ya está guardado en GitHub.")
        return
    token=os.environ.get("CF_TOKEN_LIMPIO","").strip()
    if not token: raise RuntimeError("Falta el token de Cloudflare.")
    base=f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/pages/projects/{PROJECT}/deployments"
    for page in range(1,5):
        data=json.loads(get_bytes(f"{base}?page={page}&per_page=20",{"Authorization":"Bearer "+token}))
        if not data.get("success"): raise RuntimeError("Cloudflare rechazó la consulta.")
        deployments=data.get("result") or []
        for dep in reversed(deployments):
            url=(dep.get("url") or "").rstrip("/")
            if not url.startswith("https://") or not url.endswith(".bnt-pelota.pages.dev"):continue
            try: sample=get_bytes(url+"/icon-192.png")
            except (urllib.error.HTTPError,urllib.error.URLError,TimeoutError):continue
            if hashlib.sha256(sample).hexdigest()!=EXPECTED["icon-192.png"]:continue
            retrieved={"icon-192.png":sample}
            for name,sha in EXPECTED.items():
                if name=="icon-192.png":continue
                body=get_bytes(url+"/"+name)
                if hashlib.sha256(body).hexdigest()!=sha:raise RuntimeError("Los archivos no coinciden con el ícono aprobado.")
                retrieved[name]=body
            PUBLIC.mkdir(parents=True,exist_ok=True)
            for name,body in retrieved.items():(PUBLIC/name).write_bytes(body)
            print("Íconos BNT Pelota recuperados y verificados: 192, 512, Apple y favicon.")
            return
        if len(deployments)<20:break
    raise RuntimeError("No se encontró el ícono original en los despliegues antiguos.")

if __name__=="__main__":
    try:recover()
    except Exception as e:
        print(f"Restauración del ícono pendiente: {e}",file=sys.stderr)
        sys.exit(1)
