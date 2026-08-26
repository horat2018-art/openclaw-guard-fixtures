import json, pathlib, sys, tempfile
ROOT=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent/'src'))
def load(name): return json.loads((ROOT/'fixtures'/name).read_text())
def temp_fixture(name='01_normal_small.json'):
 d=tempfile.TemporaryDirectory(); p=pathlib.Path(d.name)/'source';p.mkdir();(p/'evidence.json').write_text(json.dumps(load(name)));return d,p
