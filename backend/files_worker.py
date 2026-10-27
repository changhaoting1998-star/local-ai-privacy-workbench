"""Short-lived parser worker. stdout is one bounded JSON result; stderr is suppressed."""
import json, os, resource, sys
from backend.files_extract import extract_local,FileError,MAX_FILE

def main():
    # CPU/output/open-file caps supplement the parent wall-clock timeout. macOS PDFKit
    # reserves large VM ranges, so a hard RLIMIT_AS would disable native OCR.
    resource.setrlimit(resource.RLIMIT_CPU,(40,40))
    resource.setrlimit(resource.RLIMIT_FSIZE,(32*1024*1024,32*1024*1024))
    resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    def audit(event,args):
        if event.startswith('socket.'):raise PermissionError('Network disabled in parser worker')
    sys.addaudithook(audit)
    try:
        data=sys.stdin.buffer.read(MAX_FILE+1)
        if len(data)>MAX_FILE:raise FileError('file_too_large',413)
        result=extract_local(data,sys.argv[1])
    except FileError as exc:result={'error':exc.code,'status':exc.status}
    except BaseException:result={'error':'extraction_failed','status':503}
    sys.stdout.write(json.dumps(result,ensure_ascii=False))
if __name__=='__main__':main()
