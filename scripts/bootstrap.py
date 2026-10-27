"""Optional operator helper; browser first-run /api/setup is preferred."""
import argparse,getpass,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.app import create_app
p=argparse.ArgumentParser();p.add_argument('--username',required=True);a=p.parse_args()
password=getpass.getpass('New password (12+ chars): ')
create_app().state.create_user(a.username,password)
print('Local account created; password was not logged.')
