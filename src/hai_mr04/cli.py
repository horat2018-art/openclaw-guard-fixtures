import argparse,json
from .pipeline import run
def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument("source");a=p.parse_args(argv);print(json.dumps(run(a.source),sort_keys=True));return 0
if __name__=="__main__":raise SystemExit(main())
